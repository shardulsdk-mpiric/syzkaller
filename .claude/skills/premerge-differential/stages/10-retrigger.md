# Stage 10: Re-trigger and corpus carry-over

Re-trigger when: a picked series posts a new version, a deferred series lands
its awaited version, the maintainer tip moves enough that new series no longer
apply, or a harness change unlocks a dormant group.

1. Re-run stage 2 (intake) for the delta; re-run 3-4 only for changed series.
2. Base moves → new base worktree (stage 1); keep the old one until its
   findings are closed.
3. **Corpus carry-over**: stop runs, `bin/syz-db merge` the patched
   `corpus.db` files of the groups, copy the merged DB into each group's
   patched workdir, restart. Programs using syscalls a group does not enable
   are dropped at load (`FilterCandidates`), so merging across groups is safe.
   Requires the engine to persist its corpus (fork task
   `diff_corpus_persistence`); until then a diff run's `corpus.db` stays empty.
4. A new ledger row per re-trigger; never edit an old row.
