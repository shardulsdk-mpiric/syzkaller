# Stage 1: Base

Goal: a base kernel = the maintainer's current integration tip + the coverage
keystone, built with the campaign's `.config`.

1. Fetch the maintainer tree and the upstream next tree:
   `git fetch <maint-remote>; git fetch net-next` (MPTCP: remote `mptcp`, branch
   `export`). Topic-managed branches like MPTCP `export` are **rebuilt**, not
   appended to: an old tip may vanish from history, so pin the exact commit.
2. New worktree + branch for this campaign round (never reuse a worktree a
   previous round's findings were symbolized against):
   `git worktree add -b <campaign>-base ../linux_<campaign>_base_wt <maint>/<tip>`
3. Apply the keystone with **plain** `git am` (no `-3`). If any patch needs a
   3-way or fails: stop, and get the keystone rebased (and reviewed) first. A
   clean apply proves placement, not completeness: ask the keystone owner
   whether commits since the last keystone update added deferred/softirq
   paths that need new annotations.
4. `.config`: copy the previous round's (sanitizers, KCOV +
   `KCOV_ENABLE_COMPARISONS`, the protocol), `make olddefconfig`, then grep the
   options you rely on — `olddefconfig` silently drops ones whose deps vanished.
5. Build (in-tree is fine for a dedicated worktree):
   `nice -n 10 make -j<N> > build.log 2>&1`. On a shared box, leave threads for
   others. Check: exit 0, warnings, `vmlinux` contains the keystone's kcov hooks
   (`nm vmlinux | grep -c kcov_remote`).

Gate: base commit, keystone commit, `.config` hash recorded in the run record.

Note: a DO-NOT-MERGE commit at the tip of an export branch (e.g. "enabled by
default") is part of the base; the patched kernel must carry it too.
