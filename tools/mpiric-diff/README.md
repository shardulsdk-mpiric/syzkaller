# mpiric-diff: a working driver for syzkaller's differential fuzzing engine

`pkg/manager/diff` fuzzes a PATCHED kernel (coverage-guided, aimed at the diff),
reproduces each crash, replays the reproducer on the BASE kernel and, when base
stays clean, reports the crash as **patched-only** with a reproducer.  The
shipped `tools/syz-diff` cannot drive it: it never sets the mandatory
`diff.Config.PatchedOnly` channel, so `diff.Run` fails before booting a VM.
`mpiric-diff` is Mpiric's driver for that engine.  It uses only the engine's
exported API (`diff.Run`, `diff.Config`, `diff.Bug`, `diff.PatchFocusAreas`,
`diff.ErrPatchedAreaNotReached`, `manager.DiffFuzzerStore`,
`build.ElfSymbolHashes`, `repro.Result.CProgram`) and does not touch
`pkg/manager/diff`, so this fork stays rebaseable on upstream.

The composition is copied from `syz-cluster/workflow/fuzz/main.go`, the one
in-tree driver that works.

## Build

It must be built in-tree, with `make`: the VM handshake requires the manager
binary to carry the same git + descriptions revision as the executor.  A plain
`go build` produces a binary that refuses to start.

```
make mpiric-diff          # -> bin/mpiric-diff (also builds the executor, like `make diff`)
```

## Invocation

```
bin/mpiric-diff \
    -base    cfg/base.cfg \
    -patched cfg/patched.cfg \
    -patch   series.diff \
    -time    4h \
    [-triage 1h] [-reach 30m] [-repros 2] [-out /path/to/out] \
    [-ignore_titles 'KCSAN'] [-debug] [-vv N]
```

| flag | meaning | default |
|---|---|---|
| `-base`, `-patched` | the two `syz-manager` configs (see below) | required |
| `-patch` | `git diff` / `git format-patch` output of the series; comma-separate several files | none (symbol aiming only) |
| `-base_obj`, `-patched_obj` | `vmlinux.o` for per-function symbol hashes | `<kernel_obj>/vmlinux.o` |
| `-time` | total run time; the engine is cancelled and the summary written after it | `2h` |
| `-triage` | `MaxTriageTime`: start reproductions after this even if corpus triage is not done | `-time/2` |
| `-reach` | `FuzzToReachPatched`: abort if the patched code is not reached within this after triage | `0` = never abort |
| `-repros` | parallel reproductions to budget VMs for | `2` |
| `-possible_cutoff` | patched crash count that makes a title "possibly patched-only" | `10` |
| `-ignore_titles` | regexp of crash titles the engine must not reproduce | none |
| `-out` | output directory | `<patched workdir>/mpiric-diff` |
| `-vv` | syzkaller log verbosity | `1` (the engine logs each reproducer's reliability, and a reproducer dropped as too unreliable, only at level 1) |

One Ctrl-C (SIGINT/SIGTERM) shuts the run down gracefully and still writes the
summary; a third signal hard-exits and loses the in-memory store.  Do not wrap
the tool in `timeout(1)` either: use `-time`.  The summary is also rewritten
every 5 minutes, so a teardown hang or an OOM kill after the deadline leaves a
summary that is at most 5 minutes stale.

### Output layout

```
<out>/summary.txt, summary.json     patched-only / contested / unresolved / possibly patched-only / ignored /
                                    affects-both, each row with status + patched and base crash counts, plus the store dump
<out>/patched_only/<hash>/          one dir per patched-only title (hash = same as artifacts/crashes/<hash>)
    title, report, log, repro.syz, repro.opts, repro.c
<out>/artifacts/crashes/<hash>/     the engine's own store: patched_report, base_report, repro.prog, *.log
```

`repro.c` is written by this driver; the engine's store never writes a C
reproducer.  It appears once the second (FullRepro) delivery of a title arrives,
so give the run enough `-time` after the first "patched-only:" log line.

The summary's headline sections, in decreasing order of certainty:

- **PATCHED-ONLY**: the engine's verdict — reproducer replayed clean on base
  (3-6 runs), base never crashed with the title by itself.
- **CONTESTED**: the replay on base was clean, but the base pool (which mirrors
  the patched stream) also crashed with the same title on its own afterwards.
  The engine still counts these as patched-only (`DiffBug.PatchedOnly()` never
  un-sets `NotCrashed`); treat them as affects-both until triaged.
- **UNRESOLVED**: the engine found a reproducer but never reached a base
  verdict.  Three causes, indistinguishable in the store: the reproducer was
  below the engine's **0.4 reliability cut-off** and was dropped without a
  store update (`pkg/manager/diff/repro.go`), base crashed with a *different*
  title while verifying (logged only as `crashes both: X / Y`), or the run
  ended mid-verification.  This is the realistic outcome for a low-probability
  race (a ~35%-reliable repro lands here on a stock kernel), so it is a
  candidate finding, not noise: the row carries the engine's syz reproducer
  path (`artifacts/crashes/<hash>/repro.prog`); replay it on base by hand.
- **POSSIBLY PATCHED-ONLY**: crashed the patched kernel `-possible_cutoff` or
  more times, never crashed base, and no reproducer was found at all.
- **IGNORED**: never reproduced by the engine's own choice — the built-in
  title filter (`no output`, `lost connection`, `detected stall`, `SYZ*`),
  `-ignore_titles`, or the per-title attempt budget (7) exhausted.  Kept out
  of "possibly" so that list is not swamped by e.g. KCSAN titles.

A title whose reproducer crashes under a *different* title than the fuzzer's
original crash is booked by the engine under both (crash count under the
original, verdict under the reproducer's); the driver lists it once, under the
reproducer's title, with a note.

## The kernel pair

- **base** = the series' parent commit, **patched** = base + the series.  Both
  built from the same `.config` and toolchain, differing only by the series.
  If more than 5% of `.text` symbols differ the engine discards function-level
  aiming and falls back to files (`patch.go`); identical `.text` makes the
  driver refuse to run.
- Both keep a DWARF `vmlinux` in `kernel_obj` (coverage, focus areas, report
  symbolization) and the pre-link `vmlinux.o` (symbol hashes).  For `O=`
  builds set `kernel_obj` to the build dir and `kernel_src` to the source dir.
- Both carry Mpiric's harness kernel patches (keystone kcov + NFQUEUE) so one
  executor serves both pools.
- For race bugs, both kernels should be a **window-widening** build (scoped
  KCSAN or KASAN with the widening knobs) applied identically to base and
  patched.  The engine drops any reproducer with reliability below 0.4, so a
  35%-reliable race repro is silently lost on a stock kernel.  Widening is
  applied at boot (image init or a kernel-default patch); `mgrconfig` has no
  post-boot hook.
- Prefer a plain-crash / KASAN kernel for the run.  KCSAN *reports* are
  crashes to this engine: they are reproduced like any other and the
  `suppressions`/`interests` config keys do nothing here.  Use
  `-ignore_titles` (the engine's `IgnoreCrash` hook) to keep them out, and run
  the KCSAN two-stack channel separately.

## The two configs

- Same `target`, `enable_syscalls`, `sandbox`, executor and image conventions
  on both; different `workdir`, `kernel_obj`, `kernel`/`image` paths, and
  `http` (or leave `http` empty on base).
- **VM budget** (`vm.count` and `fuzzing_vms` in the patched config).  The
  repro loop gets `count - fuzzing_vms` VMs.  `fuzzing_vms > count` panics in
  the engine and `fuzzing_vms == count` blocks forever; the driver refuses
  both, and refuses `count - fuzzing_vms < (4N+2)/3` for `-repros N`.  Base
  verification reserves up to `min(running, count)` VMs from the **base** pool
  for 3-6 runs of at least a minute each; give base 2 or more VMs.
- Seed corpus: `<patched workdir>/corpus.db` is loaded read-only at start.
- `experimental.cover_edges` is moot (base collects no coverage); leave the
  default.

## Known foot-guns

| foot-gun | what the driver does |
|---|---|
| `PatchedOnly` unset makes the engine fail at start | always set, buffered (16), drained by its own goroutine |
| a title is delivered more than twice (Fast repro, FullRepro, then every later crash that reproduces) | de-dupe by title, keep the delivery that carries a C repro |
| the store is in-memory; a kill loses the summary | `context.WithTimeout` + graceful SIGINT; summary rewritten every 5 minutes and after `diff.Run` returns |
| deliveries still buffered when the context ends are never collected | the `PatchedOnly`/`BaseCrashes` buffers are drained after `diff.Run` returns |
| `MaxTriageTime` 0 waits for corpus triage forever | defaults to `-time/2` |
| no symbol hashes silently degrades aiming to files | reads `vmlinux.o` on both sides; loud warning on failure |
| repro reliability < 0.4 dropped without a store update or a default-visible log line | "UNRESOLVED" list (reproduced, no base verdict) with the syz repro path; `-vv` defaults to 1; widening kernel |
| base crashing with the title *after* a clean replay leaves `PatchedOnly()` true | "CONTESTED" list, base crash count on every row |
| `-debug` clamps the engine's VM count to 1, invalidating the budget | the budget check creates the pool with the same debug flag |
| one flaky base crash of a title masks that title for the rest of the run (`EverCrashedBase`) | not mitigated (engine behaviour); short runs, note in triage |
| header-only hunks (e.g. `protocol.h`) aim weakly | rely on the `.c` files' function aiming |
| `experimental.focus_areas` regexes are unanchored substrings (`tcp` matches `mptcp`) | `PatchFocusAreas` anchors its own; anchor any you add by hand |
| snapshot mode is unsupported by the engine | run executor-runner mode |
| base-VM errors can spin the verification loop | bounded only by `-time` |

## Attribution

Extends syzkaller (Google) and builds on the BRF harness work by Hung and Sani
(UC Irvine).  Cite both in any external use.
