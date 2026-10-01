# sctp_kcov_keystone -- softirq kcov coverage for net/sctp

Three-patch series, `net/sctp` plus its two headers
(`include/net/sctp/{sctp,structs}.h`, `associola.c`, `endpointola.c`,
`input.c`, `sm_sideeffect.c`; 109 insertions, 1 deletion).

## What it adds

`net/sctp` has no kcov annotations at all, and almost the entire chunk
state machine runs outside the owning task: `sctp_rcv` pushes packets
straight into the endpoint's or association's inqueue in the receive
softirq, timers call `sctp_do_sm()` from the timer softirq, and the ICMP
error handler calls it from the receive softirq. Per-task kcov sees only
the syscall-side primitives and the backlog drain.

The series captures the creating task's kcov common handle on the
**endpoint** (`sctp_endpoint_init()`, which only runs in task context),
makes every association inherit it from its endpoint (passive and
temporary associations are created in softirq where the common handle is
0, so capturing on the association would leave the server side dark),
re-syncs it on `sctp_assoc_migrate()`, and opens kcov remote sections at
the softirq entry points. Paths that become visible to the fuzzer:

| site | what becomes covered | patch |
|---|---|---|
| `sctp_assoc_bh_rcv()` / `sctp_endpoint_bh_rcv()` -- one section per packet around the chunk pop/dispatch loop | everything under `sctp_do_sm()`: passive INIT / COOKIE-ECHO handlers (incl. `sctp_unpack_cookie` and the cookie HMAC), active INIT-ACK / COOKIE-ACK, DATA/SACK/HEARTBEAT/SHUTDOWN/ABORT/ASCONF/RE-CONFIG/AUTH handlers, `sctp_eat_data`, ulpq reassembly, outq, `sctp_packet_transmit` | 2/3 |
| `sctp_generate_t3_rtx_event`, `_timeout_event`, `_heartbeat_event`, `_proto_unreach_event`, `_reconf_event`, `_probe_event` | retransmit, heartbeat, delayed SACK, autoclose, reconf, probe timers | 3/3 |
| `sctp_icmp_proto_unreachable()` | ICMP proto-unreach abort | 3/3 |

Brackets sit above `sctp_do_sm()` rather than inside it because it
re-enters itself from `sctp_cmd_process_sack()` and kcov forbids nested
softirq sections; they are placed after the sock-busy / dead-association
early exits so every opened section is closed. Guarded by
`in_serving_softirq()`, so the same functions running in process context
from `sctp_backlog_rcv()` stay on per-task kcov.

Known gap (out of scope): the pre-lookup part of `sctp_rcv()`
(`__sctp_rcv_lookup`, `sctp_rcv_ootb`, ...) runs before any endpoint or
association is in scope and stays dark.

Measured (design doc section 8.3, exact A/B, same binary and config, VM
on 2026-10-02): the remote-coverage stream went from **0 to 1572
`net/sctp` PCs** (172 functions); 41 functions / 376 PCs appear only in
the remote stream and in neither per-task stream -- the softirq-only
handlers the blind spot was about (`sctp_sf_do_5_1D_ce`,
`sctp_unpack_cookie`, `sctp_sf_do_5_1B_init`, `sctp_eat_data`, ...). No
kcov WARN in dmesg.

## Series

```
0001  sctp: add kcov remote handle capture and annotation helpers
0002  sctp: annotate the receive-softirq chunk dispatch with kcov remote coverage
0003  sctp: annotate timer and ICMP state-machine entry points with kcov remote coverage
```

Source: branch `sctp_kcov_keystone` (tip `300173089b5c4`) in the kernel
clone, worktree `open/src/kernel/linux_wt_sctp_keystone`.

## Base -- independent of the MPTCP keystone

The branch was forked from `mptcp_kcov_keystone` for convenience, but the
series does **not** use anything the MPTCP series adds: it carries its own
helpers in `include/net/sctp/sctp.h` and touches no `net/mptcp` file.

Verified (2026-10-02): all three patches `git apply --check` and
`git am --3way` clean onto a **bare** `938306d306a65` (tag
`export/20260925T104201` of `https://github.com/multipath-tcp/mptcp_net-next.git`)
with the MPTCP keystone *not* applied. They also apply clean on top of
the MPTCP series, so the two can be combined in either order.

So the base is: **`mptcp/export` at that tag, or any kernel >= v7.2-rc1
with `net/sctp`** -- the only version constraint is
`struct kcov_common_handle_id` (upstream `5a13e296a3e32`, v7.2-rc1), used
directly in 1/3.

## Apply

From the target kernel tree:

```sh
git am --3way $KERNEL_DEV_ENV_ROOT/open/src/fuzzing/syzkaller/kernel_patches/sctp_kcov_keystone/*.patch
```

(`git apply --check` each file first if you want a dry run.)

## Upstreamability

No new UAPI, no kcov-core change, `net/sctp`-local, no-op under
`CONFIG_KCOV=n` (the handle field is zero-sized without it, so no ifdefs)
-- the same per-object-handle shape already upstream in vhost, io_uring
and usbip. Upstreamable as-is after a rebase onto net-next.

Before submitting: strip the `Claude-Session:` trailer (keep
`Co-Authored-By:`), and add `Signed-off-by:` -- the patches do not carry
one yet (`git am -s`).

Design: `$KERNEL_DEV_ENV_ROOT/open/src/fuzzing/brf/.claude/designs/sctp_kcov_keystone.md`
(verification artefacts and probe in `sctp_kcov_keystone_verify/` beside it).
