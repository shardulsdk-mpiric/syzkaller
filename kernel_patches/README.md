# kernel_patches/ -- kernel-side coverage keystones

This directory holds the **only kernel-side dependencies** of the
protocol-flow fuzzing work in this tree. There are exactly two, and both
are the same shape: a small `net/<proto>`-local patch series that makes
kcov attribute the protocol's *softirq* execution (receive path, timers,
workers) to the fuzzer task that owns the socket, so coverage guidance
can see it. Everything else -- the pseudo-syscalls, the executor, the
descriptions under `sys/linux/` -- runs on an unpatched kernel.

> **The fuzzing harness itself needs no kernel patch.** Without a
> keystone the harness still runs; the fuzzer is simply blind to the
> softirq half of the protocol (it still sees the syscall half through
> ordinary per-task kcov). The keystones add the missing coverage
> stream; they add no functionality the harness calls into.

## Series

| patch series | target subsystem | base tree (verified) | what it enables |
|---|---|---|---|
| [`mptcp_kcov_keystone/`](mptcp_kcov_keystone/) (5 patches) | `net/mptcp` | `mptcp/export` tag `export/20260925T104201` (commit `938306d306a65`); any kernel >= v7.2-rc1 should take it | Coverage of the receive-softirq MP_JOIN / ADD_ADDR validation gates (token lookup, thmac, hmac, ADD_ADDR HMAC), the incoming option parser, the deferred send push, and `mptcp_worker` -- on both the active and the passive (accepted) side. |
| [`sctp_kcov_keystone/`](sctp_kcov_keystone/) (3 patches) | `net/sctp` | same base, **independent of the MPTCP series** -- applies to a bare `mptcp/export` or any kernel >= v7.2-rc1 with `net/sctp` | Coverage of the whole receive-softirq chunk state machine (`sctp_do_sm` and everything below it: INIT/COOKIE-ECHO handlers, `sctp_eat_data`, ulpq, outq, response transmit), the per-association/transport timers, and the ICMP proto-unreach path. |

Both series are instrumentation-only: no protocol behaviour changes, no
new UAPI, no change to `kernel/kcov.c`. Each is a no-op under
`CONFIG_KCOV=n`. They are independent of each other and compose in
either order (verified: SCTP on bare base, MPTCP on bare base, SCTP on
top of MPTCP all `git am --3way` clean against `938306d306a65`).

## Choosing a base

- **Minimum:** v7.2-rc1. Both series use `struct kcov_common_handle_id`
  (upstream `5a13e296a3e32`, "kcov: refactor common handle ID into
  kcov_common_handle_id", in v7.2-rc1). On an older kernel the field type
  and the `kcov_common_handle()` / `kcov_remote_start_common()` signatures
  do not match; you would have to drop the MPTCP 3/5 adaptation and use a
  bare `u64`.
- **What we actually fuzz on:** the MPTCP maintainers' `export` branch
  (`https://github.com/multipath-tcp/mptcp_net-next.git`), which is
  net-next plus the pending MPTCP queue. It is rebased regularly, so the
  base is pinned by its date tag `export/20260925T104201`, not by the
  branch name. Note `export` carries `DO-NOT-MERGE:` commits at its tip
  (it is a test tree, not a submission base).
- **For upstream submission** rebase onto `net-next` and re-run
  `git am --3way`; the touched files are stable and the series are small
  (~130 and ~110 insertions), so conflicts should be rare.

## Applying

From the target kernel tree (a worktree, never a shared checkout):

```sh
SYZ=$KERNEL_DEV_ENV_ROOT/open/src/fuzzing/syzkaller   # this repo
git checkout -b mptcp_kcov_keystone export/20260925T104201    # or your base
git am --3way $SYZ/kernel_patches/mptcp_kcov_keystone/*.patch
# and/or, independently:
git am --3way $SYZ/kernel_patches/sctp_kcov_keystone/*.patch
```

Pre-flight without touching the tree: `git apply --check <patch>` for
each file in order. The kernel then needs `CONFIG_KCOV=y`,
`CONFIG_KCOV_ENABLE_COMPARISONS=y` (optional) and the usual syzkaller
config (`docs/linux/kernel_configs.md`); the keystones add no new config
symbol. The fuzzer side needs nothing beyond `"cover": true` -- syzkaller
already enables `KCOV_REMOTE_ENABLE` with the common handle for every
executor process, which is exactly the handle these series capture.

## Trailers and upstream hygiene

The commit messages carry `Co-Authored-By:` and `Claude-Session:`
trailers recording how they were produced. For any upstream submission:

- **strip `Claude-Session:`** (internal provenance link);
- **keep `Co-Authored-By:`** (honest authorship record);
- **add `Signed-off-by:`** -- none of the patches carry one yet. `git am -s`
  adds yours on apply; otherwise `git commit --amend -s` per commit, or
  `git rebase --signoff`.

## Regenerating

The series are plain `git format-patch` output of the keystone branches
in the kernel clone; regenerate from source rather than editing a `.patch`
by hand:

```sh
K=$KERNEL_DEV_ENV_ROOT/open/src/kernel
git -C $K/linux_wt_kcov_keystone format-patch 938306d306a65..mptcp_kcov_keystone \
    -o kernel_patches/mptcp_kcov_keystone
git -C $K/linux_wt_sctp_keystone  format-patch mptcp_kcov_keystone..sctp_kcov_keystone \
    -o kernel_patches/sctp_kcov_keystone
```

(`sctp_kcov_keystone` was branched from `mptcp_kcov_keystone`, so that
range is exactly the three SCTP commits; the SCTP series does not depend
on anything the MPTCP series adds -- see the verification note in its
README.)

## Extending to a new target

A new protocol keystone (tipc, quic, ...) goes in its own
`kernel_patches/<proto>_kcov_keystone/` subdirectory with the same
contents: the numbered `format-patch` series, and a `README.md` that
states the exact base it was verified against, what softirq paths it
makes visible, and whether it is independent of the other series. Add a
row to the table above. Keep each series `net/<proto>`-local; the
pattern (capture `kcov_common_handle()` in the task that creates the
protocol object, carry it on that object, bracket the softirq entry
points with `kcov_remote_start_common()` guarded by `in_serving_softirq()`)
is documented once in the design docs below and should not need
`kernel/kcov.c` changes for any new target.

## Design documents

The reasoning, bracket-placement constraints and A/B measurements live in
the companion tree, not here:

- `$KERNEL_DEV_ENV_ROOT/open/src/fuzzing/brf/.claude/designs/mptcp_kcov_keystone.md`
- `$KERNEL_DEV_ENV_ROOT/open/src/fuzzing/brf/.claude/designs/sctp_kcov_keystone.md`
  (verification artefacts in `sctp_kcov_keystone_verify/` beside it)
- `$KERNEL_DEV_ENV_ROOT/open/src/fuzzing/brf/.claude/designs/kcov_no_uapi_coverage.md`
  -- why the no-UAPI, no-kcov-core shape was chosen over the earlier
  approach.
