# mptcp_kcov_keystone -- softirq kcov coverage for net/mptcp

Five-patch series, `net/mptcp` only (`protocol.h`, `protocol.c`,
`subflow.c`, `options.c`; 127 insertions, 20 deletions).

## What it adds

MPTCP's connection-level work does not run in the task that owns the
socket. MP_JOIN and option processing happen in the receive softirq, the
deferred send push runs from the softirq / NAPI-delegated path, and the
msk worker runs on a kworker. Per-task kcov records none of that: in
softirq `current` is whatever was interrupted, so a coverage-guided fuzzer
sees the syscall half of the protocol and nothing of the half that
decides whether a join is accepted.

The series captures the creating task's kcov common handle on the msk
and opens kcov *remote* sections keyed on it at the softirq entry points.
Paths that become visible to (and therefore guidable by) the fuzzer:

| path | context | bracket |
|---|---|---|
| MP_JOIN token lookup, SYN-ACK thmac (`subflow_req_create_thmac`), third-ACK hmac (`subflow_hmac_valid`), ADD_ADDR HMAC | receive softirq | `subflow.c` gates |
| incoming option parser (`mptcp_get_options`) | receive softirq | `options.c` |
| deferred send push (`__mptcp_subflow_push_pending` via `__mptcp_check_push` and the delegated path) | receive softirq / NAPI | `protocol.c` |
| `mptcp_worker` | kworker | task-context variant, opened unconditionally (vhost/io_uring style) |
| **passive (accepted) msks** -- every bracket above on the server side | -- | handle captured in `mptcp_init_sock()` so `sock_copy()` propagates it (patch 5/5) |

Sections are guarded by `in_serving_softirq()`, so the same code running
in process context while the backlog is drained from a syscall stays on
ordinary per-task kcov and never trips kcov's "started twice" warning.
Inline sendmsg push remains per-task, as before.

Measured (design doc section 8a, join program under `syz-execprog
-cover`): the two brackets keyed on the passive msk went from 0 PCs to
100 % of their sites in the remote stream after patch 5/5; those brackets
are provable no-ops with a zero handle, so that delta is the direct
evidence the passive path is captured.

## Series

```
0001  mptcp: add kcov remote handle capture and annotation helpers
0002  mptcp: annotate MP_JOIN/ADD_ADDR validation gates with kcov
0003  mptcp: adapt kcov handle to kcov_common_handle_id wrapper
0004  mptcp: extend kcov remote coverage to the deferred send push and worker
0005  mptcp: capture kcov handle in mptcp_init_sock so passive msks inherit it
```

Source: branch `mptcp_kcov_keystone` (tip `0ceb3b1136c12`) in the kernel
clone, worktree `open/src/kernel/linux_wt_kcov_keystone`.

## Base

Verified against the MPTCP maintainers' `export` branch at tag
**`export/20260925T104201`** (commit **`938306d306a65`**,
`https://github.com/multipath-tcp/mptcp_net-next.git`). `git am --3way`
applies all five clean on that commit.

Minimum kernel: **v7.2-rc1** -- patch 3/5 moves the handle to
`struct kcov_common_handle_id` (upstream `5a13e296a3e32`). On an older
base, use patches 1-2 and 4-5 with a `u64` handle instead.

## Apply

From the target kernel tree:

```sh
git am --3way $KERNEL_DEV_ENV_ROOT/open/src/fuzzing/syzkaller/kernel_patches/mptcp_kcov_keystone/*.patch
```

(`git apply --check` each file first if you want a dry run.)

## Upstreamability

No new UAPI, no kcov-core change, `net/mptcp`-local, no-op under
`CONFIG_KCOV=n` -- the same per-object-handle shape already upstream in
vhost, io_uring and usbip, and the same softirq-section pattern as
net/mac80211, net/bluetooth and net/nfc. Upstreamable as-is after a
rebase onto net-next.

Before submitting: strip the `Claude-Session:` trailer (keep
`Co-Authored-By:`), and add `Signed-off-by:` -- the patches do not carry
one yet (`git am -s`). Patches 1/5 and 2/5 predate the trailer
convention and carry no AI trailers at all.

Design: `$KERNEL_DEV_ENV_ROOT/open/src/fuzzing/brf/.claude/designs/mptcp_kcov_keystone.md`.
