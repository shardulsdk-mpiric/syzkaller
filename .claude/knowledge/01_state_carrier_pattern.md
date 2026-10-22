# The state-carrier pattern

The one idea the whole extension turns on. Inspired by BRF (Hung & Amiri Sani,
arXiv:2305.08782), reimplemented natively on this syzkaller fork.

## The problem

A stock syscall fuzzer throws mostly-random bytes at `sendto()` /
`setsockopt()` / `sendmsg()` and almost never gets past a protocol's own
*acceptance checks*: the MPTCP token+HMAC handshake, the SCTP verification tag
and CRC, a HID driver's device-init probe, the eBPF verifier. Each of those is a
**gate**: fail it and the kernel drops the input at the door, so the deep code
behind the gate is barely exercised. This fork exists to get **past the gate**
and fuzz that code.

## The pattern

Syzkaller already models dependencies between syscalls with **resources** (a
value one call produces and another consumes) and already supports
**pseudo-syscalls** (helper ops implemented C-side in the executor, exposed to
the fuzzer as if they were syscalls). The state-carrier pattern combines the
two:

1. A pseudo-syscall drives a real, multi-step protocol step in the executor
   (complete an MP_CAPABLE connection; bring a QUIC pair to ESTABLISHED; run the
   SCTP 4-way handshake).
2. It **captures the live state the kernel generated during that step** (the msk
   token, the SCTP verification tag, the QUIC PATH_CHALLENGE entropy) and
   threads it forward through an out-parameter typed as a syzkaller resource
   (`mptcp_pair`, `mptcp_subflow`, `sctp_assoc`, `quic_conn`, ...).
3. Later ops take that resource and operate on the live, gated connection.

The executor does the stateful / crypto work; the syzlang descriptions stay
declarative.

## Why a real resource matters

Because the carried value is a genuine syzkaller resource, the whole engine
respects the state graph for free:

- the **mutator** only sequences a join on an established pair, a chunk inject on
  a real association -- it cannot generate a call on state that was never
  produced;
- the **minimizer** keeps the producing call when it keeps a consumer;
- a **reproducer** replays the whole flow (init -> join -> drive), not a
  disconnected syscall that would do nothing on a fresh boot.

The descriptions encode this with an invalid default sentinel so a defaulted or
orphaned handle can never alias a live pool slot:

```
resource mptcp_pair[intptr]: 0xffffffffffffffff   # -> -1, rejected by the executor's `slot < 0` guard
```

Handles are real pool indices produced *only* by the producing pseudo-syscall
(`*_pair_init`, `*_join_subflow`, `*_conn_init`). The resource graph mirrors the
real executor-side dependency.

## What counts as crossing a gate

We never break crypto. The kernel computes every token, nonce, HMAC, tag and
checksum. "Crossing" means satisfying a gate whose value is **inaccessible
through the socket API** -- you can pass it only by reading it off the wire,
carrying it across packets, or computing the derived check from captured
material. Three shapes of such a gate:

- **FORGE** -- the value is never on the wire; the derived check must be computed
  from captured key material (MPTCP MP_JOIN HMAC).
- **CAPTURE + ECHO** -- the value *is* on the wire; capture it and echo it back
  (SCTP verification tag; QUIC PATH_CHALLENGE entropy).
- **ENCRYPTED-UNDER-UNEXPOSED-KEY** -- the value returns encrypted under a key
  one side never sees (QUIC Retry / NEW_TOKEN; identified, not built).

The unifying property is socket-API-inaccessibility, not secrecy. (A useful
discipline when surveying a new protocol: after the gate that *first* looks
decisive, ask what gate sits behind it -- an outer userspace-supplied gate, e.g.
QUIC's TLS/AEAD, can hide a kernel-generated inner gate where the real edge
lives. Removing an outer gate in a test configuration proves harness
portability, not edge portability.)

## The two mechanisms

### Mechanism 1: echo-back of a kernel-generated secret

Capture a value the kernel issued and present it in the next packet so a mutated
or injected packet still authenticates. We own both endpoints over loopback, so
this is capture-and-replay, not forging an attacker's position.

- MPTCP: the msk token / key material captured during `pair_init` lets an
  injected MP_JOIN SYN carry a token the kernel's softirq lookup accepts.
- SCTP: the verification tag is sniffed off the wire during `pair_init` (it is
  not exposed by any getsockopt) and stamped onto an injected packet so
  `sctp_vtag_verify` passes and the crafted chunk reaches its handler.
- QUIC: a NFQUEUE wire engine captures the PATH_CHALLENGE entropy from the
  plaintext 1-RTT frame and echoes it in PATH_RESPONSE so path validation
  (`crypto_memneq`) succeeds and migration completes.

Each echo-back op pairs with a **negative control** (echo a wrong/zero value) so
the gate is demonstrably real, not bypassed.

### Mechanism 2: constructed validity

Build a structurally valid deep payload so the fuzzer reaches the real handler
instead of bouncing off the first length/type check:

- SCTP **typed chunk grammars** -- craft a chunk with correct type, length and
  sequence fields (RECONF, and DATA / SACK / FORWARD-TSN as increments) so
  parsing reaches the chunk handler.
- eBPF **struct_ops** -- generate a program the **verifier** accepts (a semantic
  gate, not a crypto one), so the kernel actually installs and runs the callback.

## Wire-level mutation and injection

Two executor-side techniques reach code a sockets-only fuzzer cannot construct:

- **Egress mutation (M-WIRE).** `executor/common_linux_mptcp_nfq.h` installs an
  NFQUEUE rule via raw netlink and mutates protocol packets *on egress, after the
  kernel built them*, so checksums and kernel-computed fields are real and we
  flip exactly one field. The MPTCP mutation ops live in
  `executor/common_linux_mptcp_mut.h`; a UDP variant of the same engine serves
  QUIC (`common_linux_quic_nfq.h`).
- **Direct injection (M-CARRY).** For SCTP the executor crafts a full packet
  (common header + one attacker-shaped chunk) with a recomputed CRC32c
  (Castagnoli, reflected) and the captured vtag, and injects it via a raw
  socket. This reaches reject/validation paths that cannot be expressed as a
  sequence of socket calls.

## Map of the planes

Every surface is expressed across the same three planes (see 06 for the recipe):

```
sys/linux/*_flow.txt(.const)   <- descriptions: what the fuzzer may call (syzlang)
executor/common_linux_*.h      <- C carriers: what actually runs (stateful/crypto work)
pkg/structops/ (struct_ops)    <- generator: constructed-validity artifact builder
pkg/vminfo/linux_syscalls.go   <- pseudo-syscall registration (or syz-manager panics)
kernel_patches/                <- optional coverage annotation (no new UAPI; see 03)
```
</content>
