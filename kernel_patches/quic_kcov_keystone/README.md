# quic_kcov_keystone -- softirq kcov coverage for net/quic

Two-patch series, `net/quic` only (`socket.h`, `socket.c`, `packet.c`;
69 insertions, 1 deletion).

## What it adds

In-kernel QUIC (net/quic, Xin Long / lxin, RFC 9000) has no kcov
annotations, and the entire RX frame-validation state machine runs
outside the task that owns the socket. Incoming packets arrive through
the UDP tunnel encap callback in the **receive softirq**
(`quic_udp_rcv()` -> `quic_packet_rcv()`); when the socket is not owned by
a user, `quic_packet_rcv()` dispatches straight into
`quic_packet_process()` -> `quic_frame_process()` and the per-frame-type
`*_process()` handlers (`quic_frame_stream_process`,
`quic_frame_crypto_process`, `quic_frame_connection_close_process`, ...).
Per-task kcov records none of it: in softirq `current` is whatever was
interrupted, so a coverage-guided fuzzer sees the syscall side of the
protocol and nothing of the RX validation that decides whether a packet
is accepted or tears the connection down.

The series captures the creating task's kcov common handle on the QUIC
connection and opens a kcov *remote* section keyed on it at the softirq
dispatch point. Paths that become visible to (and guidable by) the
fuzzer:

| path | context | bracket |
|---|---|---|
| `quic_packet_process` -> header-protection removal, AEAD decrypt, `quic_frame_process` and every per-frame `*_process` handler, connection teardown | receive softirq | `quic_packet_rcv()` fast path |
| server-side handshake (`quic_request_sock_create/lookup/backlog_tail`, `quic_accept_sock_exists`, long-header parse) | receive softirq | same bracket |
| **accepted (server-side child) connections** | -- | handle captured in `quic_init_sock()`, which runs for the child in `accept()` task context (`quic_accept_sock_init()`) |

Where the handle is captured: `quic_init_sock()`, which only ever runs in
task context -- `socket()` for a client/listener, and `accept()` for the
server-side child (after `quic_accept()`'s `memset` clears the cloned
copy, `quic_accept_sock_init()` re-runs `quic_init_sock()` on the child,
so it inherits the accepting task's handle). There is no separate
"connection" object in this QUIC: the connection *is* the socket.

The section is guarded by `in_serving_softirq()`, so the same code running
in process context while the backlog is drained from a syscall
(`quic_backlog_rcv()` under `release_sock()`) stays on ordinary per-task
kcov and never trips kcov's "started twice" warning. The bracket sits at
`quic_packet_rcv()` rather than inside `quic_packet_process()` because the
latter re-enters itself for coalesced packets and kcov forbids nested
softirq sections; the outer section covers all re-entries.

## Measured (VM-verified 2026-10-04)

Exact A/B, same static probe binary, same config, loopback fake-keys QUIC
exercise, `KCOV_REMOTE_ENABLE` collector (probe + method in `verify/`,
mirrors the SCTP keystone's measurement):

| stream | kernel | net/quic functions | net/quic PCs |
|---|---|---|---|
| **remote** (collector area; keystone sections only) | control `quic_fuzz_kasan` (no keystone) | **0** | **0** |
| **remote** (collector area; keystone sections only) | `quic_fuzz_keystone` | **27** | **226** |
| per-task (probe runs the exercise itself) | control | 142 | 1134 |
| per-task (probe runs the exercise itself) | keystone | 142 | 1134 |

The remote stream goes **0 -> 226 net/quic PCs** (27 functions) with the
only delta being these two patches. The per-task baseline is **identical**
(142 functions / 1134 PCs) with and without the series -- the keystone
only *adds* the softirq attribution, it changes nothing per-task.

**Softirq-only recovery** (9 functions in the keystone remote stream and
in *neither* per-task stream -- coverage per-task kcov cannot see at all):
`quic_frame_connection_close_process`, `quic_packet_rcv`,
`quic_backlog_rcv`, `quic_request_sock_{create,lookup,backlog_tail}`,
`quic_accept_sock_exists`, `quic_get_msg_addrs`, `quic_inq_event_recv`.

**Precision of the claim:** these numbers are coverage of the RX
packet/frame-processing paths reached over a loopback connection
negotiated with `disable_1rtt_encryption` (the TEST config the Phase-3
wire-mutation driver uses so short-header packets are plaintext on the
wire). This is an *existence proof* of the attribution, not a fuzzing-run
reach number. In this short exercise the softirq-reached validation sites
that landed in the remote stream were the connection-teardown /
handshake-dispatch paths; stream-DATA frames were drained promptly and so
ran mostly in the backlog (process context), where per-task kcov already
records them. Under the fuzzer's longer-lived connections the full set of
`quic_frame_*_process` handlers is reached in softirq; take the campaign's
own `.extra` stream for any reach claim.

## Falsification gate (self-inflicted-crash check)

The MPTCP keystone work has a history of kcov machinery self-inflicting
crashes, so the annotation was explicitly falsified before being called
shippable:

- 40x stress of the softirq remote section on the **keystone** kernel:
  40/40 clean, **no kcov WARN, no KASAN splat, no BUG** (dmesg empty).
- 40x stress on the **control** kernel: 40/40 clean, dmesg empty.
- Crash profiles **identical** (both clean). No crash bucket named after
  the instrumentation (no `kcov_*`, no handle/annotation path).

The zero-handle path was also checked against the kcov-remote API:
`kcov_check_handle()` returns `zero_valid` for a zero common id (no WARN),
`kcov_remote_start()` misses the lookup and no-ops without setting
`kcov_softirq`, and `kcov_remote_stop()` early-returns when `!kcov_softirq`
-- the start/stop pair is a balanced no-op when the task has no remote
coverage enabled.

## Series

```
0001  quic: add kcov remote handle capture and annotation helpers
0002  quic: annotate the receive-softirq frame dispatch with kcov remote coverage
```

Source: branch `quic_keystone` (tip `a11d90dffff05`) in the kernel clone,
worktree `open/src/kernel/linux_wt_quic_keystone`.

## Base

Forked from `quic_fuzz` (tip **`cd83d12e730d4`**, "uapi: register
IPPROTO_QUIC=261 + SOL_QUIC=288"), i.e. net-next-based net/quic at
**v7.3-rc2** plus the QUIC uapi registration. `git am --3way` applies both
patches clean on that commit (verified 2026-10-04).

Minimum kernel: any with `net/quic` and `struct kcov_common_handle_id`
(upstream `5a13e296a3e32`, v7.2-rc1), used directly in 1/2.

## Apply

```sh
git am --3way $KERNEL_DEV_ENV_ROOT/open/src/fuzzing/syzkaller/kernel_patches/quic_kcov_keystone/*.patch
```

(`git apply --check` each file first for a dry run.)

## Reproducing the coverage number

Everything needed to reproduce the 0 -> 226 number independently is in
`verify/` -- no syzkaller needed, just the kernel and a C compiler:

1. Build two kernels from the same `.config` (QUIC=y + KCOV + KASAN):
   one at `cd83d12e730d4` (control), one with this series applied
   (keystone). The config used is the `quic_fuzz_kasan` `.config`
   (`CONFIG_IP_QUIC=y`, `CONFIG_KCOV=y`, `CONFIG_KCOV_INSTRUMENT_ALL=y`,
   `CONFIG_KASAN=y`).
2. `gcc -Os -static -o quic_kcov_probe verify/quic_kcov_probe.c`
3. Boot each kernel (loopback is enough; `nokaslr` keeps PCs mapping
   straight to kallsyms). In the VM:
   ```sh
   ./quic_kcov_probe remote 1 > cov_remote.txt     # keystone-collector stream
   ./quic_kcov_probe task   1 > cov_task.txt        # per-task baseline
   cp /proc/kallsyms kallsyms.txt
   ```
4. `python3 verify/bucket.py kallsyms.txt cov_remote.txt` -- on the
   keystone kernel this prints the 27 net/quic functions / 226 PCs; on the
   control kernel it prints 0.

The probe is a faithful port of the Mpiric syzkaller executor's QUIC
connection bring-up (`common_linux_quic.h`: fake per-level crypto secrets,
the selftest handshake), so the exercise it runs is the same protocol flow
the Phase-3 harness drives. It opens a `KCOV_REMOTE_ENABLE` collector in
the parent, forks, and runs the QUIC exercise in the child: any net/quic
PC that lands in the parent's area can only have arrived through a keystone
remote section.

`verify/` artefacts: `quic_kcov_probe.c`, `bucket.py`,
`keystone_remote_buckets.txt`, `control_remote_buckets.txt`,
`keystone_task_buckets.txt`, `control_task_buckets.txt`,
`keystone_remote_only_funcs.txt`.

## Per-file coverage report (for the maintainer)

`verify/COVERAGE.md` is the per-file net/quic coverage table (covered /
total instrumented PCs per file, the maintainer's own coverage shape),
captured from a **bounded** run of the **full QUIC op-set** (conn_init
`disable_1rtt=1` -> Phase-2 post-handshake drivers -> Phase-3 wire
mutation, seeded) on the keystone kernel via `syz-execprog -cover` +
`syz-cover`. Headline: net/quic **2193 / 5121 PCs (42.8%)** with the full
op-set, of which **1235 / 5121 (24.1%)** is reached in the RX softirq and
attributed only because of this keystone (flat without it). Run parameters
and the `quic_full.prog` op-set are recorded there. That full-op-set run
itself produced **0** BUG/WARN/KASAN on the keystone kernel (the
real-harness half of the falsification gate).

## Upstreamability

No new UAPI, no kcov-core change, `net/quic`-local, no-op under
`CONFIG_KCOV=n` (the handle field is zero-sized without it, so no ifdefs)
-- the same per-object-handle shape already upstream in vhost, io_uring
and usbip, and the same softirq-section pattern as net/mac80211,
net/bluetooth, net/nfc and the sibling MPTCP/SCTP keystones. Upstreamable
as-is after a rebase onto net-next.

Before submitting: strip the `Claude-Session:` trailer (keep
`Co-Authored-By:`), and add `Signed-off-by:` (`git am -s`).

Design: `$KERNEL_DEV_ENV_ROOT/open/src/fuzzing/brf/.claude/designs/quic_kcov_keystone.md`.
Siblings: `../mptcp_kcov_keystone/`, `../sctp_kcov_keystone/`.
