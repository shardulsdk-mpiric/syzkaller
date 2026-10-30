---
name: premerge-differential
description: >-
  Run a pre-merge differential fuzzing campaign end to end: fuzz the patch
  series currently in review on a kernel mailing list (base = the maintainer's
  export/next tip, patched = base + the chosen pending series) with
  tools/syz-diffrepro, and report patched-only regressions to maintainers before
  merge. Use whenever starting, preparing, re-triggering, or monitoring such a
  campaign: pulling pending series from patchwork, deciding which series are
  worth fuzzing (ROI, staleness, reachability), stacking and rebasing them,
  building base/patched kernels, writing the syz-diffrepro configs, preparing a
  fuzzing machine, launching with a canary, watching a run, merging corpora
  between runs, or keeping the campaign's run record. Also use when asked
  "which MPTCP/QUIC/... patches are in review", "set up the next differential
  run", or "what did run X fuzz".
---

# Pre-merge differential fuzzing campaign

A campaign is a pipeline. Each stage has a gate; a stage that fails its gate
blocks the next one. Load a stage file only when you reach that stage.

| # | stage | file | gate (must hold to move on) |
|---|-------|------|------------------------------|
| 1 | Base | `stages/01-base.md` | base = current maintainer tip + keystone, applies with plain `git am`, builds |
| 2 | Intake | `stages/02-intake.md` | every pending series listed with lore link; date cutoff stated; exclusions applied |
| 3 | Triage | `stages/03-triage.md` | every series has a recorded PICK / DEFER / DROP with reason |
| 4 | Stack | `stages/04-stack.md` | each group's series apply together on base; every rebase human-reviewed |
| 5 | Build | `stages/05-build.md` | base + each patched kernel built from one `.config`; keystone present on both |
| 6 | Config | `stages/06-config.md` | enabled syscalls reach the code each picked series changes |
| 7 | Machine | `stages/07-machine.md` | VM budget fits; binaries, kernels, image deployed; revs match |
| 8 | Launch | `stages/08-launch.md` | canary shows programs executing before the long run |
| 9 | Monitor | `stages/09-monitor.md` | health checked on a schedule; every crash triaged |
| 10 | Re-trigger | `stages/10-retrigger.md` | corpus carried; new series versions re-run through 2-4 |

The run record (`stages/records.md`) is kept from stage 1 onward, not written
at the end.

## Standing rules (from campaigns that went wrong)

1. **The fuzzer must reach what you patch.** A series in the patched kernel
   that no enabled syscall drives is dormant: it costs build and conflict
   effort and tells you nothing. Judge reachability against the actual
   `enable_syscalls`, not the descriptions that exist.
2. **Keystone on both sides, always.** Never run without the coverage keystone
   (`kernel_patches/<proto>_kcov_keystone`). If it does not apply, block.
3. **A series that will not apply blocks; it is never silently skipped.** Drop
   it with a recorded reason, or rebase it and have a human review the
   placement. A 3-way merge that "applies" is not reviewed.
4. **No stale series.** Check last on-list activity and whether it was
   concluded elsewhere (a maintainer reworked it and credited the author).
   Patchwork "pending" states hold years of dead entries.
5. **Base = the maintainer's current export/next tip**, not a net-next merge
   base: that keeps already-merged work out of the diff so "patched-only"
   means "caused by the pending series".
6. **Canary before every long run.** Watch qemu CPU and "executed programs" /
   coverage in the log. Process counts and free RAM look fine during a boot loop.
7. **Rev match.** syz-diffrepro, syz-manager and executor from one commit.
8. **Every series a human reads about carries a lore link**
   (`https://lore.kernel.org/<list>/<message-id>/`), in chat tables and in
   files. Patchwork ids alone cannot be looked up on lore.
9. **What is the user's to decide:** which series are in (triage verdicts are
   recommendations), any rebase whose correctness a reviewer would question,
   disposition of a finding, and anything sent to a list or maintainer.

## Where things live

- **This skill (public, tracked):** process, scripts. No findings, no machine
  addresses, no run data.
- **Run record (private, outside any repo):** `<run-root>/<campaign>/` (see
  `stages/records.md`). Run data can contain crash reports and reproducers.
- Machine inventory and per-campaign state: the user's memory notes, not here.

## Scripts

All take paths as arguments; run Python with `python3 -I`.

- `scripts/pw_intake.py` — pending series from patchwork → `series.json`,
  `candidates.tsv` (latest version per series, with msgid + lore URL), pinned mboxes.
- `scripts/apply_check.sh` — standalone apply of every candidate on base +
  per-patch failure breakdown.
- `scripts/staleness.py` — last on-list activity + concluded-elsewhere evidence.
- `scripts/hwprobe.sh` — read-only capability probe of a fuzzing host
  (`ssh host 'bash -s' < hwprobe.sh`).

Related skill: `crash-reproducer` (stage 9, reproducing what a run caught).
Engine reference: `tools/syz-diffrepro/README.md`, `.claude/knowledge/04_differential.md`.
