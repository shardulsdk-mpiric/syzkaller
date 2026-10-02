# The extension, end to end

How this fork extends Syzkaller for stateful protocol-flow fuzzing. Read this
to understand *what was added and why*; `docs/linux/mptcp_protocol_fuzzing.md`
has the per-op MPTCP reference, and `.claude/ONBOARDING.md` has the practical
setup.

Attribution: this builds on **Syzkaller** (Google) via **BRF** (Hung & Amiri
Sani, UC Irvine; arXiv:2305.08782), whose state-carrier pseudo-syscall pattern
this generalizes to network protocol flows. Extension, not a new platform.

## The problem it addresses

A stock syscall fuzzer throws mostly-random bytes at `sendto()` /
`setsockopt()` and almost never gets past a protocol's own acceptance checks:
handshake crypto (MPTCP token + HMAC), verification tags and CRC (SCTP),
device-init probes (HID), the eBPF verifier (`struct_ops`). So the deep code
behind those checks is barely exercised. This fork is built to get **past the
gates** and fuzz that code.

## The core mechanism: state-carrier pseudo-syscalls

Syzkaller models dependencies between syscalls with *resources* (a value one
call produces and another consumes). BRF added *pseudo-syscalls*: helper ops,
implemented C-side in the executor, exposed to the fuzzer as if they were
syscalls. We combine the two:

- A pseudo-syscall drives a real, multi-step protocol step in the executor
  (e.g. complete an MP_CAPABLE connection, or inject one MP_JOIN SYN).
- It **captures the live state the kernel generated** (the msk token, the
  MP_CAPABLE keys, the SCTP verification tag) and threads it forward through an
  out-parameter typed as a syzkaller resource (`mptcp_pair`, `mptcp_subflow`,
  `mptcp_token`, ...).
- Because the carried value is a real resource, the mutator and minimizer
  respect the state graph: joins run on established pairs, teardown races are
  expressible, and a reproducer replays the whole flow rather than a
  disconnected syscall.

This is the whole trick. The executor does the stateful/crypto work; the
syzlang descriptions stay declarative.

## Two honest ways past a gate

We never break crypto. The kernel computes every token, nonce and HMAC. We get
past the gate by one of:

1. **Echo-back of a kernel-generated secret.** Capture a value the kernel
   issued (MPTCP token / HMAC key, SCTP vtag) and echo it in the next packet so
   a mutated or injected packet still authenticates. We own both endpoints over
   loopback, so this is capture-and-replay, not forging.
2. **Typed grammars.** Build structurally valid deep payloads (e.g. SCTP
   `RECONF` / `DATA` / `SACK` / `FORWARD-TSN` chunks with correct type, length
   and sequence fields) so the fuzzer reaches the real handler instead of
   bouncing off the first length/type check.

## Wire-level mutation and injection

`executor/common_linux_mptcp_nfq.h` installs an NFQUEUE rule via raw netlink and
mutates protocol packets on egress *after* the kernel built them (so checksums
and the kernel-computed fields are real, and we flip exactly one field).
`executor/common_linux_mptcp_mut.h` holds the mutation ops. For SCTP we also
inject crafted chunks directly with CRC32c (Castagnoli, reflected) and the
captured vtag recomputed. This reaches the reject/validation paths a
sockets-only fuzzer cannot construct.

## Surfaces

| surface | the gate we get past | key files |
|---|---|---|
| MPTCP | MP_JOIN token + HMAC handshake; teardown-race orderings | `sys/linux/socket_mptcp_flow.txt`, `executor/common_linux_mptcp*.h` |
| SCTP | verification tag + CRC32c; typed chunk grammars | `sys/linux/socket_sctp_flow.txt`, `executor/common_linux_sctp.h` |
| HID (uhid) | device GET/SET_REPORT init probes | `sys/linux/dev_uhid_responder.txt`, `executor/common_linux_uhid.h` |
| eBPF `struct_ops` | the eBPF verifier | `pkg/structops/`, `executor/common_linux_structops.h` |

## eBPF `struct_ops`: generate -> load -> register -> exercise

Some kernel paths run only through a verifier-accepted BPF program.
`pkg/structops/` generates a semantically valid `struct_ops` program (MPTCP
packet scheduler, TCP congestion control, BPF qdisc). The executor loads it
through a **libbpf-free loader** (raw `bpf()` syscalls: BTF_LOAD / PROG_LOAD /
MAP_CREATE(STRUCT_OPS) / UPDATE / LINK_CREATE), registers it, and then
**exercises** it so the callbacks actually run -- most tooling stops at "does it
load?". Programs are compiled host-side with `BPF_NO_PRESERVE_ACCESS_INDEX`
(no CO-RE relocations), which keeps the loader upstreamable.

## Coverage into asynchronous code: kcov keystones

Much protocol code runs in softirq / workqueue context (SCTP receive, MPTCP's
passive paths), which stock `kcov` cannot attribute -- so the fuzzer neither
reports nor steers into it. The series in `kernel_patches/` carry the fuzzer's
coverage handle onto the connection object (the msk, the SCTP endpoint/assoc),
so async code both reports coverage *and* guides the fuzzer. This reuses the
existing per-object coverage-handle mechanism (the same approach vhost /
io_uring / usbip use), so there is **no new kernel UAPI**. The patches are
optional: the harness runs without them, just coverage-blind on those paths.

## Pre-merge differential: tools/syz-diffrepro

Built on syzkaller's own diff engine. It fuzzes a base-vs-patched kernel pair
aimed at the changed code, reproduces a crash, and replays it on the base to
classify patched-only regressions -- catching a regression before it merges.
See `tools/syz-diffrepro/README.md`.

## Durable corpus (struct_ops)

The `struct_ops` corpus stores the *generative spec*, not a compiled
kernel-specific blob, and re-materializes each input host-side against the live
kernel's BTF at the manager queue boundary. So a run survives a kernel rebase
and picks up where it left off instead of starting cold. See
`pkg/structops/materialize/`.

## The recipe for adding a surface or op

1. **Describe it** in a `sys/linux/*_flow.txt` file: the pseudo-syscall, its
   arguments, and the resource(s) it produces/consumes.
2. **Add any flag constant in three places:** the `.txt` enum, the `.txt.const`
   value, and the executor `#define`. (A missing `.const` -> "defined for none
   of the arches".)
3. **Implement it** in an `executor/common_linux_*.h` carrier: do the stateful
   work, capture state into the out-param.
4. **Register the pseudo-syscall** in `pkg/vminfo/linux_syscalls.go` or
   syz-manager panics when a config enables it.
5. **Regenerate + build:** `make descriptions`, then a full `make` (not just
   `make executor`) before starting a campaign, or syz-manager hits a
   revision-mismatch fatal.
6. **Decide coverage:** if the new path runs in softirq/workqueue context, it
   needs a keystone (see `kernel_patches/`) to be visible and guided.

## Map of the moving parts

```
sys/linux/*_flow.txt(.const)      <- descriptions (what the fuzzer can call)
executor/common_linux_*.h         <- C carriers (what actually runs)
pkg/structops/                    <- eBPF struct_ops generator + materialize
pkg/vminfo/linux_syscalls.go      <- pseudo-syscall registration
kernel_patches/                   <- optional kcov keystones (no UAPI change)
tools/syz-diffrepro/                <- pre-merge differential driver
docs/linux/mptcp_protocol_fuzzing.md  <- MPTCP op-set reference
```
