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
- **brief:** `tools/syz-diffrepro/README.md`.
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
  handlers. RECONF has landed; DATA / SACK / FORWARD-TSN grammars are the next
  increments.
- **keywords:** sctp, chunk, grammar, reconf, data, sack, fwd-tsn, vtag.

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

### upstreaming_clean_fixes
- **status:** open.
- **brief:** upstream syzkaller contribution process (CONTRIBUTING / the
  project's CLA).
- **goal:** route clean, non-protocol fixes to google/syzkaller via `origin`.
- **keywords:** upstream, google/syzkaller, contribute, CLA, origin.
