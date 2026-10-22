# Reproducer strength (trigger engineering)

A capability axis distinct from *reaching* code: once the fuzzer reaches a bug,
how reliably can the harness **recreate the conditions that trigger it**, so a
standalone reproducer works instead of relying on volume to stumble into the
state by accident.

(Capability framing only. Full design, build order and review gate:
`.claude/designs/reproducer_strength_taxonomy.md` in the BRF tree. Build no lever
without the owner review that doc gates.)

## The core insight

The kernel is nondeterministic. A bug can appear during a long fuzzing run yet
resist a standalone reproducer whenever the trigger depends on **hidden state the
run stumbled into by volume** -- sustained pressure across procs / VMs / boots /
millions of executions. A naive minimized program fails not because the bug is
absent but because it does not *deliberately* recreate that hidden state.

So "reproducer strength" is not one trick (not just races). It is
**trigger-engineering: a toolbox with one lever per source of hidden state.**

## The taxonomy (source of hidden state -> lever)

| # | source of hidden state | why repro-hard | lever |
|---|---|---|---|
| 1 | **timing races** (SMP / softirq-vs-process / workqueue window) | a single-thread repro can't time the window | concurrency amplification: `-procs`/`-smp` (size to CPU, not RAM), collision-seed ops that pair the two racing operations, injected delays to widen the window, CPU pinning |
| 2 | **heap / SLAB layout** (UAF/OOB needs a specific adjacency/size-class) | a long run churns the allocator into shape by accident | heap grooming: spray/defrag the target cache, chosen alloc/free patterns, size-class selection, `SLAB_TYPESAFE_BY_RCU` awareness |
| 3 | **deferred free / RCU grace periods** | the UAF window depends on whether a grace period elapsed | grace-period control (force/delay via `rcu_barrier`/`synchronize_rcu` pressure); recognize type-stable-but-reused objects |
| 4 | **accumulated global state** (counter near overflow, near-full table, fragmented pool, high refcounts) | the path is reached only from an accumulated state | warm-up / priming sequences: drive the subsystem to state X, then trigger; explicit state-builder ops; longer op chains |
| 5 | **uninitialized / stale memory** (value-dependent, KMSAN-class) | the trigger depends on garbage in reused memory | controlled poisoning: free objects with *chosen* contents into the target cache |
| 6 | **error / cleanup paths under pressure** (alloc-failure, queue-full, `-ENOMEM` cleanup) | only reached under resource pressure | fault injection (FAILSLAB / `should_fail`), deliberate memory/queue pressure, forced short reads/writes |
| 7 | **preemption / interrupt interleaving** (even on 1 CPU) | needs an IRQ/signal/timer/softirq at a precise window | interrupt/timer/signal injection; for net, inject packets to fire the softirq at the right moment |
| 8 | **per-boot randomization** (KASLR, SLAB freelist randomization, stack offsets) | the trigger depends on a per-boot offset | pin for repro (`nokaslr`, `slab_nomerge`, no freelist-random); amplify across boots for hunting (many short-lived VMs) |
| 9 | **rare input-space combinations** | a mutation found over millions of execs that a hand-written repro never enumerates | coverage-guided depth + structure-aware mutation -- requires the async-path coverage annotation (03) as a prerequisite for softirq paths |

## Have vs. build-out

- **In hand / partial:** coverage-guided depth (#9, given the annotation of 03);
  crude race amplification via `-procs`/`-smp` (#1); cross-boot amplification via
  many VMs (#8); `nokaslr`/`slab_nomerge` repro pinning (#8).
- **Build-out (behind review, prove each on a known target before claiming it):**
  race *composition* beyond crude `-procs` (#1), heap grooming (#2, the most
  generalizable -- every UAF/OOB wants it), warm-up/priming (#4), fault injection
  (#6), RCU-window control (#3), controlled poisoning (#5), interrupt injection
  (#7).

## Why it is a general capability

Trigger-engineering is what turns "found under fuzzing" into "reproducible" -- a
general strength of the method, not an exploit toolkit. It feeds the
differential's attribution confidence (04): a reliably re-triggered crash is a
stronger, sometimes engine-level, verdict.
</content>
