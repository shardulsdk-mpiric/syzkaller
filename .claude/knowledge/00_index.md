# Knowledge base: the protocol-flow extension

Topic-level reference for *how this fork's state-carrier protocol-flow fuzzing
works*. This is the deep reference; the two front-door docs are shorter:

- `.claude/extension_overview.md` -- the architecture narrative, end to end.
  Read it first.
- `.claude/ONBOARDING.md` -- set up, build, run a campaign, contribute.

This `knowledge/` tree is the per-topic companion: one concept per file, with
the kernel/executor/description code pointers, so a term has a known home when
you are working in the code rather than reading the overview.

Attribution (binding; see `../../CLAUDE.md`): this is a fork of **Syzkaller**
(Google, Dmitry Vyukov et al.). The state-carrier idea is **inspired by BRF**
(Hsin-Wei Hung & Ardalan Amiri Sani, UC Irvine; arXiv:2305.08782) -- credited,
not a layer we sit on; this fork reimplements the pattern natively on modern
syzkaller. We present our protocol-flow work as an *extension*, never as our own
platform. Cite both Syzkaller and the BRF paper in any external material.

## Discipline for this tree

`.claude/` here is **tracked and intended to be public** (gated). Keep it a
clean capability/architecture artifact: no vulnerability detail, no crash
reports, no reproducers, no embargoed material. Describe *what the harness can
do and how*, not *what it found*.

## Reading order

| Doc | Title | One line |
|-----|-------|----------|
| 01_state_carrier_pattern.md | The state-carrier pattern | The core idea; the two gate-crossing mechanisms (echo-back, constructed-validity) |
| 02_surfaces.md | The surfaces | Per surface: the gate crossed, the carrier, the ops (MPTCP, SCTP, HID/uhid, eBPF struct_ops, QUIC) |
| 03_async_path_coverage_annotation.md | Async-path coverage annotation | Carrying the kcov handle into softirq/workqueue code; no new UAPI; upstreamable |
| 04_differential.md | Pre-merge differential | Fuzz a base-vs-patched pair, attribute a crash to the series |
| 05_reproducer_strength.md | Reproducer strength | Trigger-engineering: a lever per source of hidden state |
| 06_adding_a_surface.md | Adding a surface | The recipe and the three-plane checklist |

## Concept index (the "where is X" map)

| Term / concept | Lives in |
|----------------|----------|
| state-carrier pseudo-syscall | 01 "The pattern" |
| resource threading / dependency edge | 01 "Why a real resource matters" |
| echo-back of a kernel secret | 01 "Mechanism 1: echo-back" |
| constructed-validity / typed grammars | 01 "Mechanism 2: constructed validity" |
| gate discriminator (socket-API-inaccessible) | 01 "What counts as crossing a gate" |
| wire-level mutation / NFQUEUE egress | 01 "Wire-level mutation and injection" |
| MP_JOIN token + HMAC gate | 02 "MPTCP" |
| SCTP vtag + CRC32c; chunk grammars | 02 "SCTP" |
| uhid content-aware responder | 02 "HID (uhid)" |
| struct_ops generate -> load -> register -> exercise | 02 "eBPF struct_ops" |
| libbpf-free raw-`bpf()` loader | 02 "eBPF struct_ops" |
| QUIC fake-key handshake; PATH_CHALLENGE echo | 02 "QUIC" |
| kcov remote / common handle | 03 "What upstream already provides" |
| skb-carried handle vs in-kernel capture | 03 "Two ways to carry the handle" |
| coverage annotation ("keystone") directories | 03 "Where the annotation lives" |
| syz-diff / syz-diffrepro | 04 |
| keystone-cancels-in-the-diff invariant | 04 "The invariants" |
| trigger-engineering taxonomy | 05 "The taxonomy" |
| heap grooming / RCU window / fault injection | 05 "The taxonomy" |
| the three-plane discipline | 06 "The three planes" |
| flag constant in three places | 06 "The checklist" |
| pseudo-syscall registration (vminfo) | 06 "The checklist" |
| struct_ops durable corpus / materialize | 02 "eBPF struct_ops" + 06 |

## Related material (outside this tree)

- `docs/linux/mptcp_protocol_fuzzing.md` -- the MPTCP op-set user reference
  (the kernel config a target needs, the `enable_syscalls` entries).
- `docs/pseudo_syscalls.md` -- syzkaller's own pseudo-syscall / reproducibility
  discussion that the `*_flow.txt` descriptions cite.
- `kernel_patches/README.md` -- the optional coverage-annotation series.
- `tools/syz-diffrepro/README.md` -- the pre-merge differential driver.
</content>
</invoke>
