# Frames: types, the dispatch table, and every validation / protocol-violation site

Frames are the content of a decrypted QUIC packet: STREAM data, ACKs, flow-control
updates, connection-ID management, path validation, close. This is the richest
validation surface in the implementation and the most important doc for a fuzzer —
it maps every frame type to its parser and enumerates, with `file:line`, every
place a frame is rejected and which transport error code results. It pairs with
the packet layer (`03_packet.md`, which decrypts and then calls into here) and the
queues (`05_streams.md`, which the parsed frames feed).

Spec: RFC 9000 §12, §19 (frame formats and rules), RFC 9221 (DATAGRAM).
Code: `net/quic/frame.c` (3439 lines), `net/quic/frame.h`; transport error codes
in `include/uapi/linux/quic.h:213-239`.

## Frame types (frame.h:19-47)

| type | name | type | name |
|------|------|------|------|
| 0x00 | PADDING | 0x14 | DATA_BLOCKED |
| 0x01 | PING | 0x15 | STREAM_DATA_BLOCKED |
| 0x02 | ACK | 0x16 | STREAMS_BLOCKED_BIDI |
| 0x03 | ACK_ECN | 0x17 | STREAMS_BLOCKED_UNI |
| 0x04 | RESET_STREAM | 0x18 | NEW_CONNECTION_ID |
| 0x05 | STOP_SENDING | 0x19 | RETIRE_CONNECTION_ID |
| 0x06 | CRYPTO | 0x1a | PATH_CHALLENGE |
| 0x07 | NEW_TOKEN | 0x1b | PATH_RESPONSE |
| 0x08-0x0f | STREAM (FIN/LEN/OFF bits) | 0x1c | CONNECTION_CLOSE |
| 0x10 | MAX_DATA | 0x1d | CONNECTION_CLOSE_APP |
| 0x11 | MAX_STREAM_DATA | 0x1e | HANDSHAKE_DONE |
| 0x12 | MAX_STREAMS_BIDI | 0x30 | DATAGRAM (RFC 9221) |
| 0x13 | MAX_STREAMS_UNI | 0x31 | DATAGRAM_LEN |

## The dispatch table and the per-packet loop

`quic_frame_ops[]` (frame.c:2503, built by the
`quic_frame_create_and_process_and_ack` macro, frame.c:2470) maps each type to
`{frame_create, frame_process, frame_ack, frame_attr}`. `frame_attr`
(`enum quic_frame_attr`, frame.c:2478) encodes which encryption levels the frame is
legal at (`QUIC_A_I/H/0/1` = Initial/Handshake/0-RTT/1-RTT) plus
retransmittable/probing/non-ack-eliciting bits, checked by
`quic_frame_level_valid()` (frame.c:2563).

The RX driver is `quic_frame_process()` (frame.c:2589), called once per decrypted
packet from the packet layer. Per frame in the packet it:

1. rejects an empty packet (`!frame->len`) -> PROTOCOL_VIOLATION (frame.c:2597);
2. decodes the type varint; failure -> FRAME_ENCODING (frame.c:2609);
3. rejects an unknown/unassigned type (`value > QUIC_FRAME_MAX` or
   `attr == 0`) -> FRAME_ENCODING (frame.c:2615);
4. rejects a frame illegal at this packet's level -> PROTOCOL_VIOLATION, setting
   `cb->errframe` directly (frame.c:2629);
5. calls the type's `frame_process`; on `ret < 0` copies the per-frame result into
   the packet: `cb->errframe = type; cb->errcode = frame->errcode;`
   (frame.c:2644). **This is the single relay from a frame's `frame->errcode` to
   the packet's `cb->errcode`.**

## How an error becomes a CONNECTION_CLOSE — and the "silent drop" rule

This is the single most important thing to understand about frame validation here,
and it is a deliberate, systemic design, not a per-frame quirk.

Two propagation paths:

**Path A — ordinary frame processing.** The packet-layer callers build a
zero-initialized `struct quic_frame frame = {}` on the stack (packet.c:1574 and
packet.c:1987), so `frame->errcode` starts at 0 (= `QUIC_TRANSPORT_ERROR_NONE`).
After `quic_frame_process` fails, the handlers reach
`quic_packet_process_error()` (packet.c:1400), whose chokepoint is
**packet.c:1419**: `if (!cb->errcode || outq->close_pending) { kfree_skb(skb);
return err; }`. So:

- a failure that set a non-zero `frame->errcode` -> `quic_outq_transmit_close()`
  (packet.c:1434) sends a CONNECTION_CLOSE with that code;
- a failure that left `errcode == 0` -> the packet is **silently dropped**, no
  CLOSE.

**Path B — transport-parameter parsing** bypasses `cb->errcode` entirely and calls
`quic_outq_transmit_close()` directly (socket.c:2205; see below).

The systemic consequence: **almost every raw varint/short-buffer parse failure
inside an individual `_process()` function returns a "bare `-EINVAL`" that does not
set `frame->errcode`, so it resolves to a silent drop** rather than an
RFC-mandated FRAME_ENCODING close. Only *post-parse semantic* checks (offset
overflow, limit violations, state/ordering violations) set an explicit errcode and
thus actually emit a CONNECTION_CLOSE. This was verified across CRYPTO, STREAM,
ACK, NEW/RETIRE_CONNECTION_ID, PATH_*, *_BLOCKED, CONNECTION_CLOSE, and DATAGRAM.
For a fuzzer this matters two ways: (a) a malformed frame usually yields a quiet
drop + `QUIC_MIB_PKT_INVFRMDROP` (`10_mib.md`), not a close; (b) the semantic
checks below are the ones that actually drive the explicit error-close behavior.

## The transport error codes (uapi quic.h:213-239)

`NONE 0x00`, `INTERNAL 0x01`, `CONNECTION_REFUSED 0x02`, `FLOW_CONTROL 0x03`,
`STREAM_LIMIT 0x04`, `STREAM_STATE 0x05`, `FINAL_SIZE 0x06`, `FRAME_ENCODING 0x07`,
`TRANSPORT_PARAM 0x08`, `CONNECTION_ID_LIMIT 0x09`, `PROTOCOL_VIOLATION 0x0a`,
`INVALID_TOKEN 0x0b`, `APPLICATION 0x0c`, `CRYPTO_BUF_EXCEEDED 0x0d`,
`KEY_UPDATE 0x0e`, `AEAD_LIMIT_REACHED 0x0f`, `NO_VIABLE_PATH 0x10`,
`VERSION_NEGOTIATION 0x11`, and the TLS-alert range base `CRYPTO 0x0100`.

## Per-frame validation sites (the explicit-errcode ones)

Each row is a check that sets a non-zero errcode (and therefore emits a close).
"bare -EINVAL (drop)" parse failures are omitted here except where noted; assume
every `_process` also has those. All line numbers are frame.c unless stated.

### STREAM and stream-related

STREAM 0x08-0x0f — `quic_frame_stream_process` (1061). Parses stream_id, optional
offset (OFF bit 0x04), optional length (LEN bit 0x02), FIN (bit 0x01).
- offset + payload_len > 2^62-1 -> **FRAME_ENCODING** (1095).
- stream lookup error routed via `quic_frame_stream_error` (1045): `-EAGAIN` ->
  **STREAM_LIMIT** (1054), other -> **STREAM_STATE** (1056); `-ENOSTR` -> skip.
- The data-plane checks fire in `quic_inq_stream_recv` (inqueue.c) and propagate
  back via `frame->errcode = nframe->errcode` (1141): late duplicate+FIN below
  highest -> **FINAL_SIZE** (inqueue.c:220); new offset exceeds connection or
  stream limit -> **FLOW_CONTROL** (inqueue.c:233); data past a known final size ->
  **FINAL_SIZE** (inqueue.c:241); OOO FIN with conflicting final size ->
  **FINAL_SIZE** (inqueue.c:295).

RESET_STREAM 0x04 — `quic_frame_reset_stream_process` (1545). Parses stream_id,
app errcode, finalsz.
- stream lookup error -> **STREAM_STATE** (via stream_error).
- finalsz > `recv.max_bytes` -> **FLOW_CONTROL** (1581).
- finalsz < `recv.highest`, or SIZE_KNOWN and finalsz != known -> **FINAL_SIZE**
  (1586).

STOP_SENDING 0x05 — `quic_frame_stop_sending_process` (1638). Parses stream_id,
errcode. Lookup error -> **STREAM_STATE** (via stream_error). Queues a RESET_STREAM
reply.

MAX_DATA 0x10 (1702), MAX_STREAM_DATA 0x11 (1726), DATA_BLOCKED 0x14 (1922),
STREAM_DATA_BLOCKED 0x15 (1962): monotonic/auto-responder frames; the only
explicit errcode is STREAM_STATE via stream_error for the per-stream ones; raw
parse failures are bare drops.

MAX_STREAMS_BIDI 0x12 (1835) / MAX_STREAMS_UNI 0x13 (1782): max >
`QUIC_MAX_STREAMS_LIMIT` (2^60, frame.c:1780) -> **FRAME_ENCODING** (1795/1851).
Non-increasing values are silently ignored.

STREAMS_BLOCKED_BIDI 0x16 (2055) / STREAMS_BLOCKED_UNI 0x17 (2016): max > 2^60 ->
**FRAME_ENCODING** (2029/2071).

### ACK

ACK / ACK_ECN 0x02/0x03 — `quic_frame_ack_process` (1153). Parses largest, delay,
range count, first range, then (gap, range) pairs, then (ECN only) ECT0/ECT1/CE.
- largest >= `space->next_pn` (acking a never-sent PN) -> **PROTOCOL_VIOLATION**
  (1172).
- first range > largest (smallest would be negative) -> **FRAME_ENCODING** (1192).
- in-loop `gap + 2 > smallest || range > smallest - gap - 2` -> **FRAME_ENCODING**
  (1217).
- ECN count validation failure just disables local ECN (not a connection error).

### Connection IDs

NEW_CONNECTION_ID 0x18 — `quic_frame_new_conn_id_process` (1257). Parses seqno,
retire_prior_to, length (1..20), CID bytes, 16-byte reset token.
- we use zero-length DCIDs (peer must not issue CIDs) -> **PROTOCOL_VIOLATION**
  (1268).
- length/seqno-overflow/short-buffer -> **bare -EINVAL (drop)** (1279) — note:
  RFC implies FRAME_ENCODING here, but the code drops silently.
- retire_prior_to > sequence -> **FRAME_ENCODING** (1290).
- `seqno - prior + 1 > max_count` (exceeds active_connection_id_limit) ->
  **CONNECTION_ID_LIMIT** (1308).

RETIRE_CONNECTION_ID 0x19 — `quic_frame_retire_conn_id_process` (1351). Parses
seqno.
- we use zero-length SCIDs -> **PROTOCOL_VIOLATION** (1363).
- peer retires the CID this packet arrived on -> **PROTOCOL_VIOLATION** (1377).
- seqno never issued to peer -> **PROTOCOL_VIOLATION** (1388).

### Path validation

PATH_CHALLENGE 0x1a (1520): requires 8 bytes (`QUIC_PATH_ENTROPY_LEN`); short ->
bare drop (1528). Echoes a PATH_RESPONSE.
PATH_RESPONSE 0x1b (2087): requires 8 bytes; entropy mismatch -> silently ignored
(2101), not an error. Match drives migration (`07_path.md`).

### Crypto, token, done, close, datagram

CRYPTO 0x06 — `quic_frame_crypto_process` (993). offset + length > 2^62-1 ->
**FRAME_ENCODING** (1015). Reassembly-buffer overflow in `quic_inq_handshake_recv`
-> **CRYPTO_BUF_EXCEEDED** (inqueue.c:503), propagated at frame.c:1033.

NEW_TOKEN 0x07 — `quic_frame_new_token_process` (1423). Server receiving it ->
**PROTOCOL_VIOLATION** (1432, RFC 9000 §19.7 — only clients receive NEW_TOKEN).
Empty token -> **FRAME_ENCODING** (1445). (Token length cap `QUIC_TOKEN_MAX_LEN`
120, frame.h:11 — over-length is a bare drop.)

HANDSHAKE_DONE 0x1e — `quic_frame_handshake_done_process` (1469). Server receiving
it -> **PROTOCOL_VIOLATION** (1475, RFC 9000 §19.20 — only the server sends it, so a
server receiving one is the violation).

CONNECTION_CLOSE / _APP 0x1c/0x1d — `quic_frame_connection_close_process` (1873).
Transport variant (0x1c) carries the triggering frame type; the APP variant
(0x1d) does not. Malformed fields -> bare drop (reasonable: the peer is tearing
down). On success it sets state CLOSED and returns `frame->len` (1919) — a
CONNECTION_CLOSE always ends frame processing for the packet, nothing can follow
it. Counts `QUIC_MIB_FRM_INCLOSES` (frame.c:1900); the send side counts
`QUIC_MIB_FRM_OUTCLOSES` (frame.c:858).

DATAGRAM / DATAGRAM_LEN 0x30/0x31 — `quic_frame_datagram_process` (2223). For
DATAGRAM_LEN the length is explicit; for DATAGRAM it is the rest of the buffer.
payload too large for the advertised `max_datagram_frame_size` ->
**PROTOCOL_VIOLATION** (2249, RFC 9221 §3). Note DATAGRAM does *not* propagate the
inqueue errcode back to `frame->errcode` (2262) — an asymmetry vs CRYPTO/STREAM;
likely benign since dgram-recv failures are resource-class, but worth knowing.

PADDING 0x00 (1500) and PING 0x01 (1514): cannot fail.

## The generic parse helpers (common.c)

`quic_get_var` (common.c:195), `quic_get_int` (common.c:231), `quic_get_data`
(common.c:264), `quic_get_param` (common.c:359) all return C-falsy 0 on a short
or malformed buffer. The near-universal frame.c idiom is
`if (!quic_get_var(...)) return -EINVAL;` — which, per the silent-drop rule above,
leaves `frame->errcode == 0`. There is **no** call site in frame.c where a raw
varint-decode failure is itself turned into an explicit FRAME_ENCODING errcode;
the only place that happens is the dispatcher's top-of-loop *type*-varint read
(frame.c:2609). Every FRAME_ENCODING in the per-frame list above is a post-parse
semantic check.

## Transport parameters

`quic_frame_parse_transport_params_ext` (frame.c:3172) parses the peer's transport
parameters (the enum `QUIC_TRANSPORT_PARAM_*` is in frame.h:49-72). It applies
defaults, guards against duplicate params with a `param_seen[]` bitmap (RFC 9000
§7.4, frame.c:3206), and returns `-EINVAL` on any violation. It takes no
`quic_frame` and sets no errcode itself; the caller
`quic_sock_set_transport_params_ext()` (socket.c:2205) maps the result to a close:
ordinary failure -> **TRANSPORT_PARAM (0x08)**, and the one special case
`-EPROTONOSUPPORT` from version selection -> **VERSION_NEGOTIATION (0x11)**, via a
direct `quic_outq_transmit_close()` (this is Path B above).

Notable parameter handling:
- **DISABLE_1RTT_ENCRYPTION (0xbaad)** (frame.c:3317): a client (`!is_serv`) must
  see a zero-length value or it rejects it; a server accepts any length and skips
  the content. Sets `disable_1rtt_encryption` — see `02_handshake_crypto.md` for
  how this disables 1-RTT protection. Built as a zero-length param on send
  (frame.c:3027).
- **GREASE_QUIC_BIT (0x2ab2)** (frame.c:3327): must be zero-length.
- **MAX_DATAGRAM_FRAME_SIZE (0x0020)** (frame.c:3351): clamped to
  `QUIC_PATH_MAX_PMTU`; this value feeds the DATAGRAM PROTOCOL_VIOLATION check
  above.
- role-restricted params rejected on the wrong side:
  ORIGINAL_DESTINATION_CONNECTION_ID / RETRY_SOURCE_CONNECTION_ID /
  PREFERRED_ADDRESS / STATELESS_RESET_TOKEN are server-only (client rejects if it
  is the server).
- bounds: MAX_UDP_PAYLOAD_SIZE must be in `[1200, 65527]`; ACK_DELAY_EXPONENT
  <= 20; MAX_ACK_DELAY < the max; ACTIVE_CONNECTION_ID_LIMIT >= 2 (clamped to 8);
  MAX_IDLE_TIMEOUT below the min is rejected.
- mandatory-param post-checks (RFC 9000 §7.3, frame.c:3425): missing
  INITIAL_SOURCE_CONNECTION_ID (both roles), or client missing
  ORIGINAL_DESTINATION_CONNECTION_ID / (on retry) RETRY_SOURCE_CONNECTION_ID ->
  failure.

`quic_frame_build_transport_params_ext` (frame.c:2909) is the TX side (no
validation; writes our already-validated config).

## Fuzzing relevance

This is the densest reachable validation surface once a connection is up. The
semantic checks above (FINAL_SIZE, FLOW_CONTROL, STREAM_LIMIT/STATE,
CONNECTION_ID_LIMIT, PROTOCOL_VIOLATION, FRAME_ENCODING) are exact, well-localized,
and each maps to a transmitted CONNECTION_CLOSE, so a harness can confirm it hit
one by the emitted close (and `QUIC_MIB_FRM_OUTCLOSES`). The systemic silent-drop
behaviour on raw parse errors means many malformed-frame mutations produce only
`QUIC_MIB_PKT_INVFRMDROP` with no close — worth modelling so a harness does not
mistake a quiet drop for "nothing happened." The role-restricted frames (NEW_TOKEN
to a server, HANDSHAKE_DONE to a server) and the transport-parameter parser are
compact, high-signal targets. (The silent-drop vs RFC-FRAME_ENCODING gap is noted
here as a documentation point about this code's behaviour; this KB does not assess
it as a defect.)

## Cross-references

- Where decrypted packets call `quic_frame_process`, and INVFRMDROP: `03_packet.md`.
- The inqueue data-plane checks STREAM/CRYPTO propagate (FINAL_SIZE, FLOW_CONTROL,
  CRYPTO_BUF_EXCEEDED): `05_streams.md`.
- disable_1rtt_encryption mechanism: `02_handshake_crypto.md`.
- Connection-ID set operations NEW/RETIRE call: `06_connid.md`. Path frames: `07_path.md`.
- The MIB counters (INCLOSES/OUTCLOSES/INVFRMDROP): `10_mib.md`.
