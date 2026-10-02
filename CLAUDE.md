# CLAUDE.md -- shardulsdk-mpiric/syzkaller

Working context for Claude Code and human contributors in this **fork of
Syzkaller**. The fork extends Syzkaller with a layer for **stateful
protocol-flow fuzzing** of Linux kernel transport-security protocols.

If you are new, read `.claude/ONBOARDING.md` first.

## What this fork is

A fork of google/syzkaller that adds pseudo-syscalls and tooling to fuzz
*protocol state machines* -- MPTCP, SCTP, HID (uhid), and eBPF `struct_ops` --
by carrying a connection's real state (kernel-issued tokens, HMAC keys,
verification tags) across a program. That lets the fuzzer get **past the
protocol's acceptance gates** -- handshake crypto, verification tags,
checksums, the eBPF verifier -- into the deep handler and reject code a
stateless, random-byte fuzzer is rejected from at the first check.

- `.claude/ONBOARDING.md` -- get set up, build, run a campaign.
- `.claude/extension_overview.md` -- how the extension is built (architecture).
- `docs/linux/mptcp_protocol_fuzzing.md` -- the MPTCP op-set reference.

## Authorship & attribution (binding, non-negotiable)

```
Syzkaller (Google, Dmitry Vyukov et al.)
  -> fork: BRF, the eBPF Runtime Fuzzer
     (Hsin-Wei Hung & Ardalan Amiri Sani, UC Irvine; arXiv:2305.08782)
     -> this fork: a protocol-flow extension
```

- This is an **extension**, not a new platform. Never present Syzkaller or BRF
  as ours, never rename the project, never strip upstream attribution.
- Preserve `LICENSE`, `AUTHORS`, `CONTRIBUTORS`. Cite **both** Syzkaller and
  Hung & Amiri Sani's BRF paper in any external material.
- License: Apache-2.0.

## What is ours vs. upstream

Everything not listed here is upstream syzkaller. Our additions:

- `executor/common_linux_{mptcp,mptcp_crypto,mptcp_mut,mptcp_nfq,sctp,uhid,structops}.h`
  -- executor-side state carriers, wire mutation, responders, and the BPF loader.
- `sys/linux/socket_mptcp_flow.txt`, `socket_sctp_flow.txt`,
  `dev_uhid_responder.txt` (each with a hand-maintained `.const`) -- the
  pseudo-syscall descriptions.
- `pkg/structops/` -- the eBPF `struct_ops` program generator (+ `materialize/`
  for host-side re-materialization of the corpus against live BTF).
- `kernel_patches/` -- optional, apply-ready kcov "keystone" series (no new
  UAPI) that make softirq/workqueue coverage visible. See its `README.md`.
- `tools/syz-diffrepro/` -- a pre-merge differential driver built on syzkaller's
  own diff engine (base vs. patched, aimed at a diff). See its `README.md`.
- `docs/linux/mptcp_protocol_fuzzing.md`, `CLAUDE.md`, `.claude/` -- docs and
  working context.

## How to work here

- **Session contract.** At session start read `.claude/tasks/index.md` (small,
  always). When a request matches a task's keywords, mention it and **ask
  before loading** that task's brief. See `.claude/tasks/README.md`.
- **Build / test.** Standard syzkaller (`make`, `make executor`, `make
  descriptions`). The protocol harness needs the executor built against current
  kernel UAPI headers -- build inside the target VM or on an up-to-date host.
  Target-kernel config requirements are in
  `docs/linux/mptcp_protocol_fuzzing.md`.
- **Adding a flag constant** needs it in THREE places: the `.txt` enum, the
  `.txt.const` value, and the executor `#define`. A missing `.const` yields a
  "defined for none of the arches" error.
- **Adding a `syz_*` pseudo-syscall** also needs it registered in
  `pkg/vminfo/linux_syscalls.go`, or syz-manager panics when a config enables
  it. The full recipe is in `.claude/extension_overview.md`.
- **Upstreaming.** Clean, non-protocol fixes belong upstream at google/syzkaller
  (remote `origin`), under the project's CLA. Protocol-surface work stays on
  this fork's feature branches (remote `fork`).

## Public-repo discipline

This fork is **public**. Keep it a clean engineering artifact.

- No unpublished vulnerability details, reproducers for unfixed bugs, or crash
  dumps in the tree. Bug-finding records live outside this repo.
- Commit as a consistent contributor identity; preserve Syzkaller + BRF
  attribution on every external artifact.
- `githooks/` carries a pre-commit/pre-push guard; keep it active with
  `git config core.hooksPath githooks` (see `.claude/ONBOARDING.md`).

## Maintaining this file

Update it directly when the fork's layout, the attribution chain, or the
session contract changes. Do not re-run `/init` -- it would clobber the
hand-built sections above.
