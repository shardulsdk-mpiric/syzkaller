# Task index

Single source of truth for the open development and usage threads in this fork.
Claude reads this at session start to know what is in flight, and uses keywords
to route a request to the right thread. These are **public engineering
threads** -- areas a collaborator can pick up.

## How Claude should use this file

1. At session start, read this index (always -- it is small).
2. When a user message contains a keyword from a task entry, mention it and
   ASK before loading that task's brief (do not auto-load).
3. When the user signals a task switch, propose updating `status:` and
   `last touched:` here.

Each entry: `status` / `brief` (a path, or a pointer to the doc that covers it)
/ `goal` / `keywords`.

## Usage threads

### using_the_harness
- **status:** open (reference).
- **brief:** `docs/linux/mptcp_protocol_fuzzing.md` + `.claude/ONBOARDING.md`.
- **goal:** build a target kernel, configure syz-manager with the op-set, and
  run a protocol-flow campaign.
- **keywords:** run, campaign, syz-manager, config, enable_syscalls, try it,
  get started.

### differential_premerge
- **status:** open (reference).
- **brief:** `tools/syz-diffrepro/README.md`; the end-to-end campaign process
  (intake, triage, stack, build, config, machine, launch, monitor,
  re-trigger) is the skill `.claude/skills/premerge-differential/`.
- **goal:** fuzz a base-vs-patched kernel pair aimed at a diff and classify
  patched-only regressions before merge.
- **keywords:** diff, differential, pre-merge, syz-diffrepro, regression, patched.

## Development threads

### adding_a_protocol_surface
- **status:** open.
- **brief:** `.claude/extension_overview.md` ("The recipe for adding a surface
  or op").
- **goal:** add a new protocol surface or pseudo-syscall following the
  state-carrier pattern.
- **reminders:** a flag constant lives in THREE places (`.txt` + `.txt.const` +
  executor `#define`); a new `syz_*` op must be registered in
  `pkg/vminfo/linux_syscalls.go`.
- **keywords:** new surface, new op, pseudo-syscall, add protocol, carrier.

### sctp_chunk_grammar
- **status:** in progress.
- **brief:** none yet; see `sys/linux/socket_sctp_flow.txt` +
  `executor/common_linux_sctp.h`.
- **goal:** typed SCTP chunk grammars so the fuzzer reaches the real chunk
  handlers. Increment 1 (RECONF, `5c9074abd`) and increment 2
  (DATA / FORWARD-TSN / SACK + stream-reset-enable init flag, `efc9fc497`)
  have both LANDED in protocol-flow-harness. Candidate next increments:
  AUTH / ASCONF typed bodies, or deeper I-DATA reassembly / interleave state.
- **keywords:** sctp, chunk, grammar, reconf, data, sack, fwd-tsn, i-data,
  asconf, auth, vtag.

### structops_surfaces
- **status:** open.
- **brief:** `.claude/extension_overview.md` ("eBPF struct_ops") +
  `pkg/structops/`.
- **goal:** add or extend eBPF `struct_ops` generation targets (MPTCP
  scheduler, TCP congestion control, BPF qdisc) and exercise the loaded
  callbacks.
- **keywords:** struct_ops, bpf, ebpf, verifier, scheduler, congestion, qdisc,
  loader, materialize, corpus.

### coverage_keystones
- **status:** open.
- **brief:** `kernel_patches/README.md`.
- **goal:** add a kcov keystone (no new UAPI) so a new protocol's
  softirq/workqueue paths report coverage and guide the fuzzer.
- **keywords:** kcov, coverage, keystone, softirq, workqueue, remote handle,
  kernel_patches.

### differential_audit_yield
- **status:** open, HIGH PRIORITY (opened 2026-10-24, from the MPTCP aggregate
  audit retro). Reach/attribution gaps, not an engine defect.
- **brief:** none yet; retro + evidence in memory
  `project_mptcp_premerge_audit`.
- **goal:** make pre-merge differentials actually exercise the changed code and
  attribute cleanly. Work items, ranked: (1) **op-set reach** — extend the MPTCP
  op-set with the netlink genl PM *config* commands (announce/ADD_ADDR,
  REMOVE_ADDR, SET_FLAGS, SET_LIMITS, FLUSH_ADDRS, endpoint + fullmesh config,
  MP_PRIO/backup) so the limit/flag/fullmesh/retry code is reachable, not just
  aimed-at. The current op-set drives subflow create/join/close/traffic + wire
  ADD_ADDR/MP_FAIL only, so those series ran dormant. **Coordinate with brf-a1**
  (owns MPTCP harness; also logging this to their harness roadmap — reconcile to
  one source of truth). (2) **base attribution** — rebase the differential base
  to the maintainer *export tip*, not the net-next mergebase, so already-merged
  export falls OUTSIDE the diff and patched-only attributes to the pending
  on-list series alone (also makes the keystone apply on both sides). (3) apply
  the skipped high-risk series (sockmap, TLS-usage) via semantic rebase.
- **keywords:** op-set reach, pm config ops, add_addr, set_limits, fullmesh,
  differential base, export tip, attribution, sockmap, tls-usage, audit yield,
  reach vs aim, dormant code.
- **owner:** Shardul (op-set items coordinated with brf-a1).
- **last touched:** 2026-10-24.

### diff_corpus_persistence
- **status:** landed on the fork (`9c427517d`, 2026-10-29); upstream PR prep with the
  upstreaming session. Was the BLOCKER for multi-box differential runs
  with corpus merge.
- **brief:** `.claude/tasks/diff_corpus_persistence/CLAUDE.md`.
- **goal:** make `pkg/manager/diff` (and so `syz-diffrepro`) persist the
  patched-side corpus to `corpus.db`, so runs and re-triggers resume from
  learned coverage and two boxes' corpora can be merged with `syz-db merge`.
  Today the engine creates its corpus with a nil updates channel and opens
  corpus.db read-only, so every run's corpus is lost at exit. Upstream-able.
- **keywords:** corpus persistence, corpus.db, diff corpus, syz-db merge,
  corpus merge, seeds, re-trigger, resume, LoadSeeds immutable.
- **owner:** syzkaller tree session (assigned by Shardul 2026-10-29).
  Upstream send goes to the upstreaming session once it works here.
- **progress:** in progress (2026-10-29). Root cause re-verified; upstream
  master `4902417d8` has the same gap. Design notes: patched side only; no
  minimize/delete logic (the diff engine has no corpus minimization, so a merged
  DB only grows and other boxes' programs survive); a writable LoadSeeds drops
  records that fail to deserialize (stock syz-manager behaviour).
  **Decided (Shardul, 2026-10-29):** opt-in in the engine (`diff.Config.SaveCorpus`,
  which also switches LoadSeeds to repair mode), so upstream syz-cluster, which
  relies on the no-repair open, is unchanged; `syz-diff -save_corpus` default off,
  `syz-diffrepro -save_corpus` default ON. Split: fork change + VM verification
  here; upstream PR prep handed to the upstreaming session once verified.
  **Verified 2026-10-29** (dev box, MPTCP audit kernels, `open/run/corpus_persist_test/`):
  all 4 acceptance checks pass -- run1 9 seeds -> corpus.db 81 progs; run2 resumed
  with 87 seeds, SIGKILLed, DB unpacked (101); merge with a foreign SCTP/io_uring/bpf
  corpus loaded (107 seeds), grew to 143, foreign records retained; go test -race +
  make syz-diffrepro OK. Committed as `9c427517d`.
- **last touched:** 2026-10-29.

### sanitizer_instrumentation_routing
- **status:** design note only, HIGH PRIORITY (opened 2026-10-24).
- **brief:** none yet.
- **goal:** a framework that, given a changeset, classifies which bug classes
  it risks and therefore which *mutually-exclusive* sanitizer/instrumentation
  builds are needed (KASAN vs KMSAN vs KCSAN cannot coexist; UBSAN/KCOV fold
  in), then allocates VMs across the required build variants and aims each
  differential run at the relevant changed functions. Per-hunk bug-class
  classification may use an LLM API. Turns "one KASAN build for everything"
  (which missed the data-races series — KASAN can't see data races, KCSAN can)
  into evidence-driven multi-build coverage with a VM budget. Candidate
  `tooling_as_product` artifact.
- **keywords:** sanitizer routing, kasan, kcsan, kmsan, ubsan, build variants,
  vm allocation, bug-class classification, differential targeting,
  instrumentation budget, llm classifier, mutually exclusive builds.
- **owner:** Shardul.
- **last touched:** 2026-10-24.

### upstreaming_clean_fixes
- **status:** open.
- **brief:** upstream syzkaller contribution process (CONTRIBUTING / the
  project's CLA).
- **goal:** route clean, non-protocol fixes to google/syzkaller via `origin`.
- **keywords:** upstream, google/syzkaller, contribute, CLA, origin.
