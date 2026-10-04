# QUIC protocol-flow fuzzing

This fork extends syzkaller with a **stateful QUIC protocol-flow harness** on in-kernel QUIC
(net/quic): a set of state-carrier pseudo-syscalls that reach an established connection, cross
QUIC's path-validation gate, and drive the post-handshake flow, so the fuzzer reaches the
protocol-state-gated code that a stateless, random-byte fuzzer is rejected from at the handshake.

## Attribution

This work builds on two projects and cites both: **syzkaller** (Google, Dmitry Vyukov et al.),
which it forks; and **BRF**, the eBPF Runtime Fuzzer (Hsin-Wei Hung and Ardalan Amiri Sani,
UC Irvine; arXiv:2305.08782), the inspiration for the state-carrier pseudo-syscall approach.
License: Apache-2.0.

## What this adds over upstream syzkaller

- Reaches an **established** connection via the selftest fake-key path (installs keys with
  `disable_1rtt_encryption`), removing the outer TLS/AEAD gate that stops a stateless fuzzer.
- **Crosses the PATH_CHALLENGE path-validation gate** by capturing the kernel's on-wire entropy
  and echoing it in PATH_RESPONSE, a wire-aware capture-echo, not a crypto break.
- Drives the **post-handshake flow** (streams, connection-id rotation, key update, migration),
  reaching code that is unreachable without a completed handshake.
- **Mutates frames on the wire** while a test runs. With `disable_1rtt_encryption` it mutates
  unprotected 1-RTT packets to reach the protocol-validation paths; it is not mutation of
  AEAD-protected traffic. The oracle is the SNMP counters (`QuicFrmInCloses`/`QuicFrmOutCloses`),
  not raw coverage.
- Makes **softirq-RX coverage attributable** via a small kcov keystone (a handle on the
  connection object; no new UAPI; a no-op under `KCOV=n`); much of net/quic's RX path is
  otherwise invisible to the fuzzer.

## The op-set

- `syz_quic_conn_init` — open a connection and reach established via the fake-key path.
- `syz_quic_path_challenge` — capture and echo the kernel's PATH_CHALLENGE entropy to cross path
  validation.
- `syz_quic_stream_open` / stream io — drive streams.
- `syz_quic_cid_issue` / `retire` — connection-id rotation.
- `syz_quic_key_update` — 1-RTT key update.
- `syz_quic_migrate` — connection migration.
- `syz_quic_wire_mutate` — rewrite a frame on the wire (via the UDP NFQUEUE engine).

## Kernel requirements

- In-kernel QUIC (net/quic; `IPPROTO_QUIC`). Point the harness at whatever net/quic branch you
  are working on; it targets the subsystem, not a specific version.
- `CONFIG_KCOV=y` for coverage; `CONFIG_KASAN=y` recommended for memory-error detection.
- Optional: apply `kernel_patches/quic_kcov_keystone/` for softirq-RX coverage attribution (no
  new UAPI; a no-op under `KCOV=n`).

## Getting started

- Clone the fork, check out `protocol-flow-harness`, and `make` (builds `syz-manager`, the
  executor, and the struct_ops host-compile step; the first run dumps `vmlinux.h` from your
  kernel object).
- Start from the QUIC campaign config in `orchestration/quic/configs/`: point `vm.kernel` at your
  built `bzImage`, `vm.image`/`sshkey` at your rootfs, set `workdir`.
- `./bin/syz-manager -config=<your-quic.cfg>`; the web UI serves on the config's `http` port.
- Smoke-check: the log shows "layout self-check: N structs match kernel BTF", `exec total`
  climbs, and the SNMP counters move on an established connection (the handshake gate is crossed).

## Reproduce the coverage attribution

With the keystone applied, a short run attributes softirq-RX coverage that stock kcov does not.
The recipe (a C probe, a bounded harness run, and `syz-cover`) is in
`kernel_patches/quic_kcov_keystone/`, so the "only-via-keystone" figure is reproducible on your
own kernel.

## Differential pre-merge fuzzing

Run the same harness on a base kernel and a patched kernel across a QUIC patch series before it
merges, aim at the changed code, and attribute a crash to the patch under review, catching a
regression in the posted-to-list window rather than months later. See the differential recipe in
`orchestration/`.

## See also

- `mptcp_protocol_fuzzing.md`, `sctp_protocol_fuzzing.md`, `structops_fuzzing.md` — the sibling
  protocol-flow and struct_ops harness surfaces in this fork.
