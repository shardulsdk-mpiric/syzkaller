# SCTP protocol-flow fuzzing

This fork extends syzkaller with a **stateful SCTP protocol-flow harness**: it
establishes a real SCTP association over loopback, captures the kernel-generated
verification tag, and injects attacker-shaped chunks that carry a valid vtag and
a recomputed CRC32c -- so the fuzzer reaches the chunk handlers behind SCTP's
acceptance checks, which a stateless, random-byte fuzzer is rejected from.

## Attribution

This work builds on two projects and cites both:

- **Syzkaller** -- Google (Dmitry Vyukov et al.), the coverage-guided kernel
  fuzzer this is a fork of.
- **BRF (BPF Runtime Fuzzer)** -- Hsin-Wei Hung & Ardalan Amiri Sani, UC Irvine
  (arXiv:2305.08782), which established the state-carrier pseudo-syscall +
  out-parameter discipline this harness generalizes to SCTP.

An extension of that lineage, not a new platform. Preserve `LICENSE`, `AUTHORS`,
`CONTRIBUTORS`; cite Syzkaller and BRF in any external presentation.

## The gate this gets past

Two SCTP acceptance checks keep a stateless fuzzer out of the deep code:

1. **The verification tag.** Every SCTP packet after the handshake must carry
   the peer's verification tag (`sctp_vtag_verify`); a wrong tag is dropped
   before any chunk handler runs. The tag is kernel-generated and is **not
   exposed by any getsockopt**.
2. **The CRC32c checksum.** A packet with a bad checksum is discarded.

The harness owns both endpoints over loopback, so the kernel runs the full
4-way INIT/COOKIE handshake itself (the cookie-HMAC gate is satisfied for real,
no userspace crypto). It **sniffs the verification tag off the wire** during the
handshake (there is no sockopt for it) and stamps that captured tag plus a
recomputed CRC32c onto each injected chunk -- so injected chunks pass the gate
and reach their handler. This is capture-and-replay on a connection we own, not
forging.

## What this adds over upstream syzkaller

A **stateful SCTP op-set** (`sys/linux/socket_sctp_flow.txt` +
`executor/common_linux_sctp.h`): pseudo-syscalls that carry a live SCTP
association (and its captured vtags) across a program via an `sctp_assoc`
resource, so chunk injection runs against a genuine established association and
the minimizer/mutator respect the dependency edge.

## The op-set

All produce/consume the `sctp_assoc` resource, so a reproducer replays the whole
flow rather than a disconnected syscall.

| pseudo-syscall | what it does |
|---|---|
| `syz_sctp_pair_init(flags)` -> `sctp_assoc` | establish a real SCTP association on loopback (client `connect()` + server `accept()`, `SOCK_STREAM`/`IPPROTO_SCTP`); the kernel runs the full INIT/COOKIE handshake. `flags`: `SCTP_INIT_CAPTURE_VTAG` opens an AF_PACKET loopback sniffer during the handshake and records both directions' init tags on the slot (the tag is not exposed by any getsockopt) |
| `syz_sctp_pair_close(assoc)` | close the fds, free the slot (consuming) |
| `syz_sctp_drive_traffic(assoc, data, len)` | `sctp_sendmsg()` on the association, reaching the DATA / reassembly path |
| `syz_sctp_inject_chunk$captured(assoc, chunk_type, payload, len, vtag_mode)` | craft a full SCTP packet (common header + one attacker-shaped chunk of `chunk_type` carrying `payload`) with the **captured** server vtag + a recomputed CRC32c, and inject it via a raw `IPPROTO_SCTP` socket toward the server, so `sctp_vtag_verify` passes and the chunk reaches its handler |
| `syz_sctp_inject_chunk$zero` / `$wrong` | the same injection with a zero / wrong vtag -- negative controls the gate rejects (bound to their own `$variant` so the fuzzer does not waste ~2/3 of injects on packets dropped before any handler) |

The `chunk_type` byte and `payload` bytes are fuzzer-mutated across the SCTP
chunk surface (DATA / SACK / RECONF / FORWARD-TSN / ...). Typed per-chunk
grammars (structurally valid DATA / SACK / FORWARD-TSN values that satisfy each
handler's length/sequence gates) are an in-progress increment on top of this
generic injector.

## Kernel requirements

Build the target kernel with:

- `CONFIG_IP_SCTP=y` (built-in, not a module, so the association and raw
  injection work in the executor's network namespace)
- `CONFIG_KASAN=y`, `CONFIG_KCOV=y`, `CONFIG_KCOV_ENABLE_COMPARISONS=y`
- raw-socket injection runs inside the executor's unshared netns (it holds
  `CAP_NET_RAW` there); no special privilege config beyond a standard syzkaller
  sandbox is needed

Coverage into SCTP's **softirq receive path** (where injected chunks are
processed) is invisible to stock kcov. The optional keystone series under
`kernel_patches/sctp_kcov_keystone/` carries the coverage handle onto the SCTP
endpoint/association so that path reports coverage and guides the fuzzer, with
no new UAPI -- see `kernel_patches/README.md`. The harness runs without it, just
coverage-blind on the receive path.

## See also

- `docs/linux/mptcp_protocol_fuzzing.md` -- the sibling MPTCP harness.
- `.claude/extension_overview.md` -- the extension architecture end to end.
- `docs/pseudo_syscalls.md` -- upstream syzkaller's pseudo-syscall model.
