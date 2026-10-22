# Pre-merge differential

Fuzz a *base-vs-patched* kernel pair aimed at a changed-code region and classify
a crash that reproduces on the patched kernel but not the base -- i.e. catch a
regression a feature series introduces, before it merges.

Built on syzkaller's own differential engine (`tools/syz-diff`). The fork adds
`tools/syz-diffrepro` (the run + attribute driver) and an orchestration recipe
for building the kernel pair.

## The shape

```
base    = <base-ref>    + coverage annotation   -> bzImage (no feature series)
patched = <patched-ref> + coverage annotation   -> bzImage (with it)
          where  base-ref..patched-ref  ==  exactly the feature series under test
```

The engine fuzzes both, reproduces a crash, replays it on the base, and
attributes a patched-only crash to the series, with `focus_areas` aimed at the
series' changed files. A crash that also fires on the base is a pre-existing bug,
not a regression.

## The invariants (why the recipe exists)

1. **Worktrees, never the main checkout.** Both arms build from disposable git
   worktrees so the shared kernel clone is never mutated.
2. **Same coverage annotation on BOTH arms, so it cancels in the diff.** The
   annotation series (03) is applied identically on base and patched, so the only
   content delta the attribution sees is the feature series. This is
   load-bearing, not cosmetic: if an async path is coverage-dark on both arms the
   fuzzer's aim cannot steer there, and a regression living on that path is
   missed.
3. **Identical `.config` + toolchain + host.** Same seed config, same
   `olddefconfig`, same `make`, same machine. The build asserts the
   diff-critical options survive `olddefconfig` (KASAN, KCOV, DEBUG_INFO,
   NETFILTER_NETLINK_QUEUE, NF_TABLES) and fails loudly otherwise, because
   `olddefconfig` can silently drop options when the seed came from a different
   base.
4. **DWARF + retained `vmlinux.o` on both.** `syz-diff` needs symbols and
   `vmlinux.o` for `PatchFocusAreas` / `ElfSymbolHashes`; `CONFIG_DEBUG_INFO=y`
   from the seed and the build leaves `vmlinux.o` in the `O=` dir.

## Gotchas

- **Annotation-vs-series conflict.** When both the annotation series and the
  feature series touch the same subsystem directory, the build applies the
  annotation with `git am --3way` and aborts loudly on conflict -- resolve by
  hand in the worktree or rebase the annotation, then re-run.
- **Same host/toolchain for both arms** (not necessarily the same host as the
  executor; the kernel host-build is fine even where the *executor* host-build is
  constrained by header mismatch).
- **Reproducibility footer.** The build prints base/patched `git describe` plus
  the annotation commit; record it with any result.

## Where it lives

- Driver: `tools/syz-diffrepro/` (see its `README.md`); engine: `tools/syz-diff`.
- Kernel-pair build recipe and the orchestration script:
  `.claude/designs/diff_kernel_pair_recipe.md` in the BRF tree
  (`orchestration/diff/build_kernel_pair.sh`). The annotation series the recipe
  `git am`s live in this fork at `kernel_patches/{mptcp,sctp}_kcov_keystone/`.
- Thread: `differential_premerge` in `tasks/index.md`.

## Relationship to reproducer strength

The differential engine's confidence in an attribution rises with how reliably
the crash reproduces across runs; the trigger-engineering levers in 05 (race
composition in particular) feed that reliability, and a reliably re-triggered
crash can cross the engine's repeat-count threshold to an engine-level verdict.
</content>
