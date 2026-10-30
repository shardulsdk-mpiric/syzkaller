# mptcp_kcov_keystone -- softirq kcov coverage for net/mptcp

Nine-patch series, `net/mptcp` only (`protocol.h`, `protocol.c`,
`subflow.c`, `options.c`). Patches 1-5 are the original series; 6-9 extend
it to softirq paths that live fuzzing showed were still invisible.

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
| delegated actions, `mptcp_napi_poll` | NAPI softirq | one section per dequeued subflow, keyed on that subflow's msk (patch 6/9; replaces 4/5's bracket inside `mptcp_subflow_process_delegated`) |
| passive accept, all of `subflow_syn_recv_sock` incl. `mptcp_finish_join` -> `mptcp_pm_allow_new_subflow`, `mptcp_sk_clone_init` | receive softirq | one section keyed on the listener's msk, single stop at a shared exit label (patch 7/9; replaces 2/5's inner `subflow_hmac_valid` bracket) |
| option dispatch: ADD_ADDR received/echoed, RM_ADDR, MP_PRIO, MP_FAIL, FASTCLOSE, RST | receive softirq | a second section over the non-DSS block of `mptcp_incoming_options` (patch 8/9; DSS-only packets pay nothing; replaces 2/5's inner `add_addr_hmac_valid` bracket) |
| port-join announced-listener check `mptcp_pm_announced_has_ssk` | receive softirq | `subflow_check_req`'s target-keyed section starts before it (patch 9/9) |

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
0006  mptcp: open the delegated-action kcov section per subflow in mptcp_napi_poll
0007  mptcp: extend the kcov section over the whole passive accept path
0008  mptcp: extend kcov coverage to the non-DSS option dispatch
0009  mptcp: cover the port-join announced-listener check on the SYN path
```

Source: branch `mptcp_kcov_keystone` (tip `0ceb3b1136c12`) in the kernel
clone, worktree `open/src/kernel/linux_wt_kcov_keystone`.

## Patches 6-9: measured effect

`syz-execprog -cover`, unique PCs in the remote (`.extra`) stream, same
programs before (patches 1-5) and after (1-9), PCs/denominator per function:

| function | 1-5 | 1-9 |
|---|---|---|
| `subflow_syn_recv_sock` | 2 | 48/87 |
| `mptcp_pm_allow_new_subflow` | 0 | 13/17 |
| `mptcp_sk_clone_init` | 0 | 30/96 |
| `mptcp_pm_rm_addr_received` | 0 | 8/10 |
| `mptcp_pm_add_addr_received` | 0 | 9/30 |
| `mptcp_pm_add_addr_echoed` | 0 | 4/10 |
| `mptcp_pm_mp_prio_received` | 0 | 6/9 |
| `mptcp_pm_announced_has_ssk` | 0 | 5/8 |
| `mptcp_napi_poll` | 0 | 6/53 |

Sites covered by patches 1-5 are unchanged (the one-PC drop in
`add_addr_hmac_valid` is the removed inner bracket's own stop call). No kcov
warning in ~45 minutes of smoke fuzzing. Builds clean with `CONFIG_KCOV=n`
and `W=1`.

Known gap: in `mptcp_napi_poll` the delegated-action branch itself (subflow
not owned by a user task when NAPI runs) did not occur on a 2-vCPU loopback
setup, so the 6 PCs are the "already processed" path. The section is in
place; triggering that branch is a reach problem, not an annotation one.

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
