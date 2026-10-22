---
name: crash-reproducer
description: >-
  Set up and run syzkaller crash-reproduction searches correctly — find,
  re-catch, or minimize a reproducer for a kernel crash/WARN/leak caught by the
  harness, using syz-repro and/or syz-crush. Use this whenever reproducing a
  reported crash, choosing between syz-repro and syz-crush, minimizing a caught
  crash into a C reproducer, or when a reproduction run misbehaves — fails to
  start, hangs at "executed programs: 0", or reports "no output from test
  machine", "SYZFAIL", or "mismatching manager/executor git revisions". It
  encodes the pre-flight checklist, the tool-selection decision, the launch
  procedure, and health verification so repro runs are set up right every time
  instead of being debugged from scratch.
---

# Crash reproducer search (syzkaller)

Reproducing a harness-caught crash looks trivial ("just run the tool on the
log") and is full of silent traps. A run that *looks* like it's working can be
executing nothing, and a program that *looks* like it hangs is often a stale
process or a config mistake. This skill is the checklist and decision procedure
that turns "point a tool at the log and hope" into a run you can trust — and
read the honest result of.

Two tools, two different jobs. Pick deliberately (see **Tool selection**), then
**pre-flight → launch → verify health**, never skipping verification.

The bundled scripts do the repeatable, error-prone checks; prefer them over
re-deriving the commands. They take paths/config as arguments, so they work in
any checkout:
- `scripts/preflight.sh` — gate a run before launch (rev match, config, kernel-has-bug, paths, resources)
- `scripts/health.sh` — is a running search actually executing, or silently dead?
- `scripts/cleanup.sh` — kill syz-crush/syz-repro/qemu safely (no stray VMs, no self-kill)

---

## Tool selection: syz-repro, syz-crush, or both?

They are not interchangeable. Choosing wrong wastes hours.

| | **syz-repro** | **syz-crush** |
|---|---|---|
| Job | EXTRACT + MINIMIZE a reproducer from a crash log | MASS-REPLAY one input across N VMs until the crash recurs |
| Input | `<execution.log>` | `<execution.log \| creprog.c>` |
| Behaviour | Bounded & structured: tries the crash-report prog, bisects the log, escalates timeouts, replays the whole log. Minimizes + emits a C repro on success. Gives up after a bounded attempt (~15–20 min). | Infinite by default (`-infinite`), no minimization — brute-force repetition across many VMs for as long as you let it. |
| Use it to | GET a minimal / C reproducer, or cheaply learn whether a crash reproduces at all | RE-CATCH a rare/flaky crash that syz-repro couldn't trigger in its window |

### Decision procedure

**Step 1 — characterize the crash (this IS the assessment).**
- **Hit count** in the original campaign: how many log files does the crash
  bucket have? One log (`log0` only) = rare/flaky; many = frequent, likely easy
  to reproduce.
- **Context / stack**: is the crash in `<IRQ>` / softirq / a timer / an async
  worker (timing- and race-dependent → hard), or a straight syscall path
  (synchronous → usually easy)? Grep the report for `<IRQ>`, `softirq`.
- **What you already have**: is there a `repro0` in the bucket? Then the
  campaign already reproduced it — go straight to syz-repro to *minimize*, don't
  hunt. Is there an execution `log0`? syz-repro needs it.

**Step 2 — almost always start with syz-repro on the log.** It is bounded and
high-information: either it hands you a minimal + C reproducer (done), or it
tells you the crash is hard to reproduce — cheaply. Don't open with a multi-hour
syz-crush before you know whether the thing reproduces easily.

**Step 3 — if syz-repro fails (common for rare async races): escalate to
syz-crush long mass-replay** (on the same log, many VMs, hours). syz-repro
proving it can't reproduce in its window is the *signal* to switch, not a dead
end. Rare races accumulate enough replays over a couple of hours — but remember
it is a numbers game: **attempts-per-hour is what matters** (see the note on
log-vs-candidate replay speed under Gotchas).

**Step 4 — if syz-crush catches it, feed the saved triggering program back to
syz-repro to minimize** → the C reproducer. syz-crush reproduces; syz-repro
minimizes. You often need both, in that order.

**Running both at once** only helps if you have the RAM for the combined VM
count; usually sequential (repro first, crush if needed) is more efficient.

---

## Pre-flight (gate every run)

Run `scripts/preflight.sh <config.cfg> <kernel-src-dir> [<bug-grep-regex>]` and
fix anything it flags before launching. What it checks and why each matters:

1. **Rev consistency.** syz-crush/syz-repro and the executor binary
   (`bin/linux_amd64/syz-executor`) must be the **same git revision**, or every
   VM dies instantly with `SYZFAIL: failed to recv rpc` /
   `mismatching manager/executor git revisions`. Building the Go tools does NOT
   rebuild the executor — after any tool build run `make executor` so the
   executor matches, then confirm all of (crush, repro, executor, tree HEAD)
   agree. Rebuilding one without the other is the single most common cause of a
   repro run that won't start.
2. **Config validity.** The `.cfg` must be valid JSON; `kernel_obj`, `image`,
   `sshkey`, and `vm.kernel` (bzImage) paths must exist; and `enable_syscalls`
   must contain **only syscalls this build knows** — one unknown name makes
   syz-crush refuse to start with `unknown enabled syscall`. `enable_syscalls`
   gates fuzzing generation, not log replay, so a *valid narrow* set is fine for
   replaying a log; keep it to names the build accepts rather than every op the
   log mentions.
3. **The kernel actually has the bug.** Don't assume the deployed image is
   buggy — grep the target kernel *source* for a line unique to the bug (pass a
   regex matching, e.g., the failing assertion or the guard that should have
   been there). Kernels get rebased; a fix may already be in. If the image lacks
   the bug, no run can reproduce it.
4. **Kernel + rootfs boot.** If unsure, boot once manually (see
   `references/manual-vm.md`) before committing VMs to a long run.
5. **Resources.** Disk, RAM, `/dev/kvm`. Size VM count to the host: each VM is
   `vm.cpu` cores + `vm.mem` MB; N×mem must fit free RAM with headroom, or VMs
   swap-stall into false "no output" crashes. A single VM is enough to start.

**Input correctness — the subtle one.** Decide what you're running *on*:
- Reproduce the real crash → run on the actual **`log0`** (the execution log),
  not a hand-extracted single candidate. A single candidate replays faster but
  loses the multi-program context a race may need, and is easy to get wrong
  (wrong mutation argument, zero-filled vs real payload). If you must use a
  candidate, extract it from syz-repro's own "detailed listing" of the crash
  prog, not by guessing.
- Minimize a known trigger → run syz-repro on the log, or syz-crush on a `.c`
  repro.

---

## Launch

Both tools take `-config <cfg>` and the input file, and write to the config's
`workdir` (crashes land in `<dirname(workdir)>/crashes/`). Give each run a fresh
`workdir` and a unique `http` port.

```bash
# syz-repro: bounded extract + minimize (run FIRST, usually)
nohup ./bin/syz-repro -config=repro.cfg  <crash>/log0        > repro.log  2>&1 &

# syz-crush: infinite mass-replay (escalation for rare races)
nohup ./bin/syz-crush -config=crush.cfg  <crash>/log0        > crush.log  2>&1 &
```

Run detached (survives the session). syz-crush is infinite by default; add
`-infinite=false` to stop on first crash. `-debug` dumps full VM console if you
need to see per-call behaviour. Size the VM count to the host's cores and free
RAM (see pre-flight).

---

## Verify health (never skip)

A started run is not a working run. Immediately after launch, and periodically,
run `scripts/health.sh <run.log> [<crashes-dir>] [<target-warn-regex>]`. It
distinguishes:

- **Running clean (good):** VMs up (by *correct* process name), qemu CPU
  **sustained high** (executing), 0 "no output" crashes, no SYZFAIL/mismatch.
  syz-crush only logs `instances executed` *on a crash*, so for a clean run
  silence + high CPU is success, not a stall — trust the CPU, not the log.
- **Hung program (bad):** console reaches `executed programs: 0` then goes
  silent → `no output from test machine`. The executor wedged on the first
  program. Check for an actual hang vs. a config/env issue (below).
- **Harness failure (bad):** `SYZFAIL` / `mismatching … git revisions` →
  rev-mismatch (rebuild the executor to match); `unknown enabled syscall` → bad
  `enable_syscalls`.

If a run reports a crash, confirm it's **your** crash (the real WARN/BUG
signature), not infrastructure noise — grep the crash `description` for the
target signature, not just "a crash happened". "no output from test machine" is
*not* your bug.

---

## Gotchas (each costs real debugging time)

- **The `qemu` process name is truncated to 15 chars.** `qemu-system-x86_64`
  shows up in `comm` as **`qemu-system-x86`**, so `pgrep -x qemu-system-x86_64`
  matches NOTHING — every "qemu: 0" from it is false, kills silently no-op, and
  the stray VMs left behind contend for ports/CPU/the snapshot image and make
  the *next* run fail with "no output at 0 executions" that looks exactly like a
  program hang. Always `pgrep -x qemu-system-x86` (or match the full cmdline).
- **`pkill -f '<pattern>'` self-matches your own shell** when the pattern string
  is in your command line (e.g. `pkill -f qemu-system`, `pgrep -f 'syz-crush -config'`)
  → it kills the shell running it (exit 144) mid-script. Kill by PID from
  `pgrep -x <exact-comm>`, never `pkill -f` with a self-matching pattern.
  `scripts/cleanup.sh` does this correctly.
- **Rebuilding the Go tools doesn't rebuild the executor.** The `SYZFAIL` loop
  is almost always this. `make executor` after building tools.
- **A receive-window clamp + an oversized send payload can block the executor's
  send call** → "no output". If a hand-built program hangs but the baseline
  runs, shrink the payload or drop the clamp; better, use the real candidate
  from the log. (Relevant to harness ops that deliberately clamp the window to
  force deferred/softirq delivery.)
- **A single extracted candidate ≠ the crash log.** If a candidate "runs clean"
  but never triggers, you may have the wrong mutation argument / payload, or the
  race needs the full log's context. Prefer the real `log0`.
- **Replay speed is a numbers game.** A huge `log0` replays slowly (few
  attempts/hour) — faithful but a poor vehicle for a *rare* race, where you want
  maximum attempts/hour. A small, correct, non-blocking candidate iterates far
  faster. Trade fidelity for volume once you know the minimal triggering shape.
- **Manual qemu needs `-device virtio-rng-pci`** (entropy) and the modern
  `-device <nic>,netdev=net0 -netdev user,...,hostfwd=...` net syntax, or the
  guest's crng never seeds and ssh/crypto stalls — a manual VM looks booted but
  won't accept ssh. (syzkaller's own qemu invocation has these; copy it. See
  `references/manual-vm.md`.)

---

## Cleanup

When done (or before relaunching), `scripts/cleanup.sh` kills syz-crush,
syz-repro, and all qemu VMs by correct name and PID, and verifies zero remain.
Always clean between runs — a stray VM from a previous run is the classic cause
of a mysterious "no output" on the next.

---

## Reference

- `references/manual-vm.md` — booting one VM by hand (with the entropy + net
  args that actually work) for interactive `syz-execprog -debug` diagnosis.
