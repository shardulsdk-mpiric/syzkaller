# Stage 3: Triage (is each series worth fuzzing?)

Verdicts are recommendations; the user decides. Present them as a table in
chat with a lore link per row.

## Order

1. **Clearly drop** (no runtime change the fuzzer can reach): selftests-only,
   docs, MIB/counter-only, not a patch, superseded, code outside the protocol
   core that the op-set never calls.
2. **Stale / concluded** (stage 2 evidence): drop. Changes-requested with no
   new version: defer unless the requested change is small.
3. **ROI** for the rest. Do not drop a series for being small: lock, lifetime
   and ordering fixes are where regressions hide, and they are cheap to carry.

## ROI rubric (per series)

1. Runtime change: which functions/paths, 2-4 lines.
2. Reachability against the **actual** `enable_syscalls` (read the previous
   cfg; pseudo-syscalls that return handles, not fds, cannot feed generic
   socket calls): today / config-only (name the syscalls) / needs new
   descriptions / needs a harness change (e.g. a mode the executor forces off).
3. Risk class and whether the campaign's sanitizers see it: memory lifetime /
   refcount (KASAN), UB (UBSAN), lock order (lockdep), data race (KCSAN only),
   leak (kmemleak only).
4. Cost: patch count, conflicts with base, overlap with other candidates in
   the same files.
5. Status on the list: live, superseded, changes-requested, being dropped by
   the author, already flagged by an AI reviewer (fuzzing would re-find it).
6. Verdict PICK / DEFER / DROP + confidence + run group.

## Using subagents

Fan out by area, 3 series per agent, read-only analysis, each in its own
throwaway worktree under the scratchpad. Brief = the rubric above + mbox paths
+ base branch + the previous cfg path + known harness limits (e.g. forced PM
mode). Then spot-check each agent's load-bearing claims in the code yourself
before presenting. Agents may hand-rebase conflicting series; save their
patches to `<rec>/series/rebased_unreviewed/` — they are not usable until
the user reviews the flagged points.
