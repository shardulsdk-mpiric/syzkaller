# The surfaces

One section per protocol surface. For each: the gate it crosses, the carrier
that crosses it, and the op-set. All share the state-carrier pattern (01) and the
three-plane structure (06).

Status at a glance (capability, not findings):

| surface | gate crossed | mechanism | carrier / descriptions | where it lives |
|---|---|---|---|---|
| MPTCP | MP_JOIN token + HMAC handshake; teardown-race orderings | echo-back + wire mutation | `common_linux_mptcp*.h` / `socket_mptcp_flow.txt` | `protocol-flow-harness` |
| SCTP | verification tag + CRC32c; typed chunk grammars | echo-back + constructed validity | `common_linux_sctp.h` / `socket_sctp_flow.txt` | `protocol-flow-harness` |
| HID (uhid) | device GET/SET_REPORT init probes | content-aware responder | `common_linux_uhid.h` / `dev_uhid_responder.txt` | `protocol-flow-harness` |
| eBPF struct_ops | the eBPF verifier | constructed validity | `pkg/structops/` + `common_linux_structops.h` / `bpf_struct_ops.txt` | `protocol-flow-harness` (+ a 3rd surface on a worktree) |
| QUIC | fake-key handshake; PATH_CHALLENGE echo; wire mutation | echo-back + wire mutation | `common_linux_quic*.h` / `socket_quic.txt` | worktree `syzkaller_wt_quic`, branch `quic_surface` |

---

## MPTCP

**Gate:** the MP_JOIN handshake authenticates a new subflow with a token derived
from the server key (SHA-256) and an HMAC-SHA256 over nonces. A stateless fuzzer
cannot produce a token the kernel's softirq token-lookup accepts, nor a valid
HMAC, so the join code and everything behind it stays dark.

**Carrier:** `syz_mptcp_pair_init()` establishes one MP_CAPABLE connection on
loopback (client `connect()` + server `accept()`, both `IPPROTO_MPTCP`) and
threads it through the `mptcp_pair` resource. Subflow joins run through the
kernel's own userspace path-manager netlink API (`MPTCP_PM_CMD_SUBFLOW_CREATE`)
in NORMAL mode, so the kernel computes a valid nonce/HMAC end to end -- a stock
`CONFIG_MPTCP` kernel suffices. For the injection / race ops the executor sends a
raw MP_JOIN SYN carrying the captured server token, and the NFQUEUE engine
(`common_linux_mptcp_nfq.h` + `_mut.h`) mutates the join on egress.

**Op-set** (`socket_mptcp_flow.txt`):

| op | kind | what it does |
|---|---|---|
| `syz_mptcp_pair_init` | producer -> `mptcp_pair` | establish an MP_CAPABLE pair; flags: `RWND_CLAMP` (pin the server rcvbuf so a send burst defers to softirq push), `CAPTURE_KEYS` |
| `syz_mptcp_pair_close` | consumer | close both fds, free the slot |
| `syz_mptcp_join_subflow` | `mptcp_pair` -> `mptcp_subflow` | real MP_JOIN via PM netlink; `mut_op` selects an egress mutation (`NONE` / `HMAC_FLIP` / `HMAC_ZERO` / `NONCE_FLIP`) to exercise the HMAC-failure gate |
| `syz_mptcp_subflow_destroy` | consumer | `MPTCP_PM_CMD_SUBFLOW_DESTROY` |
| `syz_mptcp_subflow_info` | non-consuming | query the parent msk (`MPTCP_INFO`) without freeing the handle -- lets the generator sequence further ops on a live subflow |
| `syz_mptcp_inject_join_syn` | non-consuming | raw MP_JOIN SYN with the captured server token: drives the incoming-join path cheaply |
| `syz_mptcp_close_server` | lifecycle, non-consuming | close only the accepted server msk (SO_LINGER), listener/client alive -- a teardown verb the generator can collide with joins |
| `syz_mptcp_disconnect` | lifecycle, non-consuming | `connect(AF_UNSPEC)` on the reused socket, driving the pm.ops reset path |
| `syz_mptcp_join_close_race` | terminal consumer | burst MP_JOIN SYNs while synchronously closing the server msk -- the close/teardown race as one op |
| `syz_mptcp_listener_close_race` | self-contained | complete N unaccepted handshakes then close the listener, racing child-forget against the worker/softirq |
| `syz_mptcp_drive_traffic` | non-consuming | push data client->server; on a `RWND_CLAMP` pair the drain is partial so the kernel flushes from the deferred-push softirq path |

The lifecycle verbs (`close_server`, `disconnect`) are deliberately
non-consuming so syzkaller's own scheduler can interleave them with joins -- the
race class then emerges from the engine's breadth rather than a hand-timed op.

Deep background on the protocol: the kernel-side MPTCP knowledge base at
`open/src/kernel/linux/.claude/knowledge/linux/net/mptcp/`.

---

## SCTP

**Gate:** SCTP guards each packet with a 32-bit **verification tag** (checked by
`sctp_vtag_verify` before any chunk handler runs) and a **CRC32c** over the whole
packet. The 4-way INIT/COOKIE handshake also carries a cookie-HMAC. A stateless
fuzzer fails the vtag/CRC at the door.

**Carrier:** `syz_sctp_pair_init()` establishes a real association on loopback
(the kernel runs the full handshake, so the cookie-HMAC is satisfied for real
with no userspace crypto) and threads it as `sctp_assoc`. The vtag is not exposed
by any getsockopt, so with `SCTP_INIT_CAPTURE_VTAG` the executor opens an
AF_PACKET sniffer during the handshake and stores both directions' init tags on
the slot. Injected chunks are crafted full packets (common header + one chunk)
with a recomputed CRC32c and the chosen vtag, sent via a raw `IPPROTO_SCTP`
socket (M-CARRY).

**Op-set** (`socket_sctp_flow.txt`):

| op | kind | what it does |
|---|---|---|
| `syz_sctp_pair_init` | producer -> `sctp_assoc` | establish association; `CAPTURE_VTAG` sniffs Vs/Vc |
| `syz_sctp_pair_close` | consumer | close fds, free slot |
| `syz_sctp_drive_traffic` | non-consuming | `sctp_sendmsg()` -> DATA / reassembly path |
| `syz_sctp_inject_chunk$captured` | non-consuming | craft + inject a chunk stamped with the **captured** vtag so `sctp_vtag_verify` passes and the chunk reaches its handler |
| `syz_sctp_inject_chunk$zero` / `$wrong` | non-consuming | negative controls the gate rejects |

The vtag mode is bound per `$variant` (not a `flags[]` arg) on purpose: it keeps
the fuzzer from spending ~2/3 of its injects on the two modes `sctp_vtag_verify`
drops before any handler runs. Coverage guidance keeps and mutates the
`$captured` programs that reach handlers; `$zero`/`$wrong` stay selectable
controls.

`chunk_type` and `chunk_payload` are fuzzer-mutated across the
DATA/SACK/RECONF/FORWARD-TSN surface. The **typed chunk grammars** (constructed
validity, mechanism 2) give those chunks correct type/length/sequence structure
so parsing reaches the handler -- RECONF has landed; DATA / SACK / FORWARD-TSN
are the next increments. See the `sctp_chunk_grammar` thread in `tasks/index.md`.

---

## HID (uhid)

**Gate:** a HID driver's `.probe` may call
`hid_hw_raw_request(HID_REQ_GET_REPORT)`, which on a uhid device *blocks in the
kernel* (up to 5 s) waiting for a `UHID_GET_REPORT_REPLY` whose id matches the
`UHID_GET_REPORT` event it queued to userspace; the reply's `data[]` is then what
the driver's parser consumes. The stock `write$UHID_*` calls never read the
request, so they can neither match the id nor carry chosen content -- the probe
times out and the deep parsers never run.

**Carrier:** `syz_uhid_create_responder()` opens `/dev/uhid`, `UHID_CREATE2`s a
device whose bus/vendor/product bind it to a chosen in-tree driver, and runs a
background thread that answers every GET/SET_REPORT with a matching reply (echoed
id, `err=0`) carrying `reply_payload` as `data[]`. The returned fd is a
sub-resource of `fd_uhid`, so the stock `write$UHID_INPUT2` /
`write$UHID_DESTROY` can be sequenced on the bound device.

**Op-set** (`dev_uhid_responder.txt`):

| op | kind | what it does |
|---|---|---|
| `syz_uhid_create_responder` | producer -> `fd_uhid_responder` | create a bound device + responder thread |
| `syz_uhid_destroy_responder` | consumer | stop/join the thread, `UHID_DESTROY` |

Target profiles (`UHID_TARGET_*`) select which driver to bind (generic,
PlayStation DualSense USB/BT, DS4, CP2112). Reply-shaping flags (`UHID_RESP_*`,
a bitmask) gate specific driver paths: `ECHO_RNUM` sets `data[0]` = requested
report id (the hid-playstation gate), `CRC32` appends a trailing CRC (the BT
gate), `SET_FAIL` acks with `-EIO`, `EXACT_LEN` drives short-reply error paths,
`WAIT_PROBE` blocks the call until the async probe's request burst is answered.

Honest scope: this edge is partial -- it reaches the deep *runtime* report
parsers that depend on a content-matched reply; other HID surface is reachable by
existing raw-gadget tooling.

---

## eBPF struct_ops

**Gate:** some kernel paths run only through a **verifier-accepted** BPF program
installed as a `struct_ops` instance. The gate is the verifier (a semantic gate,
not crypto): a byte-mutated object just fails to load.

**Carrier:** the full lifecycle is **generate -> load -> register -> exercise**,
and the last step is the point -- most tooling stops at "does it load?".

- **generate:** `pkg/structops/` is a table-driven, verifier-contract-aware C
  generator. One per-surface table (writable-field set, kfunc set, callback
  signatures, instance metadata) drives a generic body generator; the rendered C
  is compiled host-side with `clang -target bpf` against the target kernel's
  `vmlinux.h`, using `BPF_NO_PRESERVE_ACCESS_INDEX` (no CO-RE relocations, which
  keeps the loader simple and upstreamable). The generator is a source import of
  the BRF-fork struct_ops generator, reimplemented on native syzkaller (the
  surface is chosen by the syzlang blob type, not a runtime knob).
- **load:** `executor/common_linux_structops.h` loads the object through a
  **libbpf-free loader** -- raw `bpf()` syscalls: BTF_LOAD, one PROG_LOAD per
  callback, MAP_CREATE(`BPF_MAP_TYPE_STRUCT_OPS`), map update, LINK_CREATE.
- **register:** the loader always registers through a `BPF_F_LINK` struct_ops map
  + `BPF_LINK_CREATE`, so the registration dies with the returned `fd_bpf_link`
  (a link-less registration would outlive the program). The returned link can be
  driven further by the existing `bpf$` descriptions (LINK_UPDATE, LINK_DETACH).
- **exercise:** the executor then drives the subsystem so the callbacks actually
  run.

**Op-set** (`bpf_struct_ops.txt`): `syz_bpf_struct_ops_load$<surface>(obj, len)
fd_bpf_link (no_squash)`. The object travels as a `data array[int8]` blob;
`no_squash` keeps the mutator's `squashAny` from flattening it, and mutation
*re-generates* the blob rather than byte-flipping it. Landed surfaces:

| `$variant` | surface struct | kernel file | tree |
|---|---|---|---|
| `$tcp_cong` | `tcp_congestion_ops` | `net/ipv4/bpf_tcp_ca.c` | mainline |
| `$mptcp_sched` | `mptcp_sched_ops` | `net/mptcp/bpf.c` | mptcp/export |
| `$bpf_qdisc` | `Qdisc_ops` | `net/sched/bpf_qdisc.c` | mainline (demonstrated on worktree `syzkaller_wt_bpf_qdisc`) |

The third surface (`$bpf_qdisc`) is the evidence that adding a surface is "a
table, not a fork": it cost a small per-surface table plus a small *generic*
generator extension. It also surfaced the honest limits -- two wrinkles a table
alone does not cover: **per-callback kfunc gating** (enqueue vs dequeue vs common
allowed-kfunc sets) and **kernel-injected prologue/epilogue** kfuncs on
`.init`/`.reset`/`.destroy` (the generated body must leave room, not emit them).
A kfunc that needs a new C idiom (e.g. `bpf_dynptr_from_skb`) is a generator
extension, not a table row. See `.claude/designs/bpf_qdisc_structops_surface.md`
in the BRF tree for the extracted kernel contract.

**Durable corpus.** The struct_ops corpus stores the *generative spec* (surface
tag + per-callback statement AST, ~1-2 KB), not the compiled kernel-specific
recipe (60-160 KB, BTF-dominated). The recipe is re-materialized host-side
against the live kernel's BTF at the manager's request-source boundary
(`pkg/structops/materialize/`), so a run survives a kernel rebase and picks up
where it left off instead of rotting. The split lives at the boundary between
"what the fuzzer reasons about" (spec) and "what this kernel executes" (recipe),
using only public `queue`/`prog` APIs -- no syzkaller core change.

---

## QUIC

In-kernel QUIC (`net/quic`, Xin Long / lxin, RFC 9000). On a separate worktree
(`syzkaller_wt_quic`, branch `quic_surface`) because it needs a `net/quic=y`
kernel; the carrier reuses the MPTCP NFQUEUE engine (UDP variant).

**Gate(s):** the outer gate is TLS/AEAD. The carrier *removes* that in a test
configuration -- fake per-level crypto secrets (`QUIC_SOCKOPT_CRYPTO_SECRET`) +
`disable_1rtt_encryption`, mirroring the kernel's own selftest recipe
(`quic_test.c: set_fake_keys()/do_handshake()`) -- to reach ESTABLISHED cheaply.
That is **harness setup, not edge evidence** (same role as MPTCP completing a
real handshake before fuzzing). The real edge is the **inner** kernel-generated
gate: `syz_quic_path_challenge()` triggers connection migration so the kernel
emits a PATH_CHALLENGE carrying `get_random_bytes` entropy that is on the wire
but obtainable *only* off the wire; the NFQUEUE engine captures it from the
plaintext 1-RTT frame and echoes it in PATH_RESPONSE so path validation
(`crypto_memneq`) succeeds. `QUIC_PC_ECHO_WRONG` is the negative control.
(A second inner gate -- Retry / NEW_TOKEN, encrypted under an unexposed server
key -- is identified but not built.)

**Op-set** (`socket_quic.txt`), in phases:

- Phase 1: `syz_quic_conn_init` (producer -> `quic_conn`, with an out-param
  `quic_conn_state` snapshot), `syz_quic_conn_close`, `syz_quic_path_challenge`
  (the capture-echo gate).
- Phase 2 (post-handshake drivers, real socket/cmsg API only):
  `syz_quic_stream_open`, `syz_quic_stream_io`, `syz_quic_cid_issue`,
  `syz_quic_cid_retire`, `syz_quic_key_update`, `syz_quic_migrate` -- each lights
  up a deep `net/quic` file (stream/frame/inqueue/outqueue/connid/crypto/path).
- Phase 3 (wire mutation): `syz_quic_wire_mutate` flips bytes of a plaintext
  1-RTT packet (`UNKNOWN_TYPE` / `RESERVED_BITS` / `STREAM_TO_RESET`) so the
  kernel reaches the protocol-validation / teardown paths rather than only
  AEAD-reject. This is mutation of *unprotected* test-config traffic, not of
  AEAD-protected traffic -- state that precisely when describing it.
</content>
