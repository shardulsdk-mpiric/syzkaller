# Onboarding

For a colleague picking up this fork to **try the protocol-flow fuzzer** or
**contribute to it**. Assumes kernel and general Linux familiarity, not prior
syzkaller experience.

This is a fork of **Syzkaller** (Google) that extends **BRF** (Hung & Amiri
Sani, UC Irvine; arXiv:2305.08782) -- see `CLAUDE.md` for the binding
attribution. If you already know syzkaller, the one new idea is in
`.claude/extension_overview.md`; skip to "Run a campaign".

## 1. Orientation (5 minutes)

Read, in order:

1. `CLAUDE.md` -- what the fork is, what is ours vs. upstream, how to work here.
2. `.claude/extension_overview.md` -- the architecture: state-carrier
   pseudo-syscalls and the four surfaces (MPTCP, SCTP, HID, eBPF `struct_ops`).
3. `docs/linux/mptcp_protocol_fuzzing.md` -- the MPTCP op-set, with the kernel
   config the target needs.

The one-line mental model: *stock syzkaller is rejected at a protocol's
handshake/verifier gate; this fork carries the connection's real state so the
fuzzer gets past the gate into the deep code.*

## 2. Get the tree

```sh
git clone https://github.com/shardulsdk-mpiric/syzkaller.git
cd syzkaller
git config core.hooksPath githooks   # activate the commit guard (see sec. 6)
```

Remotes, by convention: `fork` = this repo (feature branches live here),
`origin` = google/syzkaller (upstream; clean non-protocol fixes go there under
the CLA). The integrated protocol-flow work -- all surfaces (MPTCP, SCTP, HID,
eBPF struct_ops) plus the keystones, `tools/syz-diffrepro`, and this `.claude/` --
lives on the `protocol-flow-harness` branch.

## 3. Build

Standard syzkaller build (Go toolchain + a C toolchain; see upstream
`docs/linux/setup.md` for host prerequisites):

```sh
make                 # manager, fuzzer, and the rest
make descriptions    # regenerate sys/gen after editing a *.txt description
make executor        # the executor alone
```

Build notes specific to this fork:

- The protocol harness executor includes current kernel UAPI (MPTCP/SCTP
  netlink, BPF). Build the executor where those headers are up to date -- inside
  the target VM, or on a host with current headers -- not against stale distro
  headers.
- After changing a `.txt`, the executor, or `pkg/structops`, run a **full
  `make`** (not just `make executor`) before starting a campaign, or syz-manager
  aborts with a revision mismatch.
- Keep build caches off a small root filesystem (`GOCACHE` / `TMPDIR` on a disk
  with room) -- syzkaller builds are large.

## 4. Build a target kernel

The target kernel needs the protocol built in plus coverage/sanitizers on.
`docs/linux/mptcp_protocol_fuzzing.md` lists the exact config for MPTCP
(`CONFIG_MPTCP`, `KASAN`, `KCOV`, built-in NFQUEUE for the mutation layer, and
leaving kmemleak off on a bug-finding kernel). For the asynchronous paths
(SCTP receive, MPTCP passive), apply the optional keystone series in
`kernel_patches/` -- see `kernel_patches/README.md` for the apply/regenerate
commands. The harness runs without the keystones, just coverage-blind there.

## 5. Run a campaign

A syz-manager config points at the built kernel image and enables the
pseudo-syscalls you want. The MPTCP doc shows the `enable_syscalls` entries for
the op-set. Start small (a few VMs), confirm the manager comes up healthy and
coverage climbs, then scale to the host's CPU (size VM count to cores, not RAM).

To replay or minimize a single program outside the manager, use `syz-execprog`
/ `syz-prog2c` as in upstream syzkaller.

## 6. Contributing

- **Add a surface or op:** follow the recipe in
  `.claude/extension_overview.md` ("The recipe for adding a surface or op").
  The two easy-to-miss steps: a flag constant lives in THREE places
  (`.txt` + `.txt.const` + executor `#define`), and a new `syz_*` op must be
  registered in `pkg/vminfo/linux_syscalls.go`.
- **Pick up a thread:** `.claude/tasks/index.md` lists open development and
  usage threads. Read it, pick one, read its brief.
- **Commit guard:** `githooks/` blocks committing content marked with the
  embargo sentinel (a dev-hygiene guard so unpublished material never lands in
  a public commit). Keep `core.hooksPath=githooks` set.
- **Upstreaming:** a clean fix that is not protocol-specific belongs at
  google/syzkaller via `origin`, under the project's CLA. Protocol-surface work
  stays on this fork.
- **Attribution:** preserve `LICENSE` / `AUTHORS` / `CONTRIBUTORS`; cite both
  Syzkaller and the BRF paper in anything external.

## Where to look when stuck

| you want to... | look at |
|---|---|
| understand the design | `.claude/extension_overview.md` |
| use the MPTCP ops | `docs/linux/mptcp_protocol_fuzzing.md` |
| apply coverage keystones | `kernel_patches/README.md` |
| run a pre-merge diff | `tools/syz-diffrepro/README.md` |
| know the general fuzzer | upstream `docs/` (syzkaller's own docs) |
