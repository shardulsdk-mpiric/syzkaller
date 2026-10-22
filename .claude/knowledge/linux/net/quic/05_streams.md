# Streams, reassembly, flow control, and loss recovery

How application data actually moves: the stream table and stream state machines
(stream.c), the receive side with CRYPTO/STREAM reassembly and receive flow
control (inqueue.c), and the send side with queueing, send flow control, and
RFC 9002 loss recovery / retransmission (outqueue.c). This is the data-plane
counterpart to the frame doc (`04_frame.md`); the frames themselves are parsed
there, this doc is what the queues do with them.

Spec: RFC 9000 §2-§4 (streams, flow control), §3 (stream state machines),
RFC 9002 (loss detection and recovery), RFC 9221 (DATAGRAM).
Code: `net/quic/stream.c`, `net/quic/inqueue.c`, `net/quic/outqueue.c`,
headers `stream.h`, `inqueue.h`, `outqueue.h`, state enums in uapi `quic.h`.

## Streams (stream.c)

A stream ID's two low bits encode who may use it (RFC 9000 §2.1):
`QUIC_STREAM_TYPE_MASK = 0x03`, low bit = initiator (0 client / 1 server),
bit 0x02 = direction (0 bidi / 1 uni) — the four values `CLIENT_BIDI 0x00`,
`SERVER_BIDI 0x01`, `CLIENT_UNI 0x02`, `SERVER_UNI 0x03` (stream.h:29-32). The
type is extracted in `quic_stream_id_valid()` (stream.c:21).

- `quic_stream_table` (stream.h:96) is a hash table of open `quic_stream`s plus
  two `quic_stream_limits` (one for what the peer advertised to us = `send`, one
  for what we advertise = `recv`). Each `quic_stream` (stream.h:34) carries
  independent `send` and `recv` substructs with their own offsets, byte counts,
  flow-control limits, and state.
- `quic_stream_find()` (stream.c:54) is an exact hash lookup.
- `quic_stream_get()` (stream.c:219) is the open-or-find entry (sock lock held):
  it validates the ID type, returns an existing stream on a hit, and on a miss
  decides between opening (`quic_stream_create`, stream.c:83) and an error. The
  error mapping is the fuzzing-relevant part: `-ENOSTR` for an already-closed/
  consumed ID (stream.c:240), `-EINVAL` for a wrong-direction or non-local ID or a
  missing `MSG_QUIC_STREAM_NEW` flag (stream.c:237, 243), and `-EAGAIN` when the
  stream-count limit would be exceeded (stream.c:246). Opening a stream opens *all*
  lower-numbered streams of the same type at once (RFC 9000 §2.1 out-of-order
  open rule, stream.c:100-103), seeding each with the negotiated per-stream-data
  limits.
- `quic_stream_id_exceeds()` (stream.c:181): for recv, checks the ID against the
  precomputed `recv.max_*_stream_id`; for send, checks both the ID and the implied
  stream count against `max_streams_*`.
- `quic_stream_max_streams_update()` (stream.c:309): when remote-initiated streams
  close, recomputes the max stream IDs so the peer can open more, signalling a
  MAX_STREAMS_UNI/BIDI send.
- `quic_stream_put()` (stream.c:264): releases a stream. Uni streams delete
  immediately; bidi streams delete only once *both* directions reach a terminal
  state (checks the other direction's state, stream.c:284-289).

**State machines** (enums in uapi quic.h:167-179):
`SEND: READY, SEND, SENT, RECVD, RESET_SENT, RESET_RECVD`;
`RECV: RECV, SIZE_KNOWN, RECVD, READ, RESET_RECVD, RESET_READ`. The transitions
are spread across files: `READY->SEND` and `SEND->SENT` (on first frame / FIN) in
the outqueue (outqueue.c:465-474, 429-434); `->RECVD` / `->SIZE_KNOWN` on FIN in
the inqueue (inqueue.c:152, 317); the **RESET_*** and **READ** transitions live in
frame.c (RESET_STREAM/STOP_SENDING handlers) and socket.c (recvmsg/sendmsg) —
*not* in these three files. (Flagged by the extracting pass: treat the stream
state story as spanning frame.c + socket.c too, and verify a specific transition
at its real site.)

Stream-count limit violation surfaces as `-EAGAIN` from `quic_stream_get()`
(a backpressure signal, not a protocol error); byte-level flow-control violations
are enforced in the inqueue (below).

## Receive path (inqueue.c)

Four lists, all in `struct quic_inqueue` (init `quic_inq_init`, inqueue.c:663):

- `handshake_list` — out-of-order CRYPTO frames awaiting in-order delivery,
  ordered by (level, offset).
- `stream_list` — out-of-order STREAM frames, ordered by (stream_id, offset).
- `early_list` — 0-RTT STREAM data received before the App crypto level is ready.
- `recv_list` — the final in-order, delivery-ready queue drained by
  `quic_recvmsg()`; holds in-order CRYPTO, events, datagrams, and stream data,
  with ordering rules at insertion (handshake ahead of data, inqueue.c:408; events
  ahead of stream/dgram, inqueue.c:635).

Reassembly:

- `quic_inq_handshake_recv()` (inqueue.c:470): CRYPTO reassembly by
  `crypto->recv_offset`. Drops a fully-covered duplicate (inqueue.c:486), enforces
  the OOO receive-buffer limit with `QUIC_TRANSPORT_ERROR_CRYPTO_BUF_EXCEEDED`
  (RFC 9000 §7.5, inqueue.c:492-505), inserts out-of-order into `handshake_list`
  ordered by offset, and on in-order delivery walks the list to splice now-
  contiguous buffered frames. In-order handshake bytes go via
  `quic_inq_handshake_tail()` (inqueue.c:385), which advances `recv_offset` and —
  for level 0 (the post-handshake App "NewSessionTicket" channel) — accumulates
  into the `ticket` buffer and fires `QUIC_EVENT_NEW_SESSION_TICKET`
  (inqueue.c:425-457).
- `quic_inq_stream_recv()` (inqueue.c:188): STREAM reassembly by
  `stream->recv.offset`/`.highest`. This is the enforcement point for receive
  flow control — it checks the new highest offset against both the connection
  limit (`inq->max_bytes`) and the stream limit (`stream->recv.max_bytes`),
  returning `-ENOBUFS` + `QUIC_TRANSPORT_ERROR_FLOW_CONTROL` on violation
  (inqueue.c:226-239), and does final-size consistency checks returning
  `QUIC_TRANSPORT_ERROR_FINAL_SIZE` (inqueue.c:220, 240, 295). Out-of-order data
  is inserted into `stream_list` ordered by offset; in-order data goes through
  `quic_inq_stream_tail()` (inqueue.c:116), which advances the offset, routes to
  `early_list` vs `recv_list` by App-crypto readiness, and on FIN fires a
  STREAM_UPDATE event, sets `recv.state`, and calls `quic_stream_put()`.
- `quic_inq_dgram_recv()` (inqueue.c:648): DATAGRAM frames — no reassembly, just a
  receive-buffer check and append to `recv_list` (unreliable/unordered).
- `quic_inq_event_recv()` (inqueue.c:605): builds a synthetic event frame if the
  app subscribed (`inq->events` bitmask) and inserts it ahead of data.

The reassembly design is TCP-OOO-queue-analogous but **frame-granular, not
byte-granular**: a single sorted list per queue, insertion by one walk with inline
dup/overlap checks, and a splice-forward step on each in-order delivery; frames
stay as separate entries (no merging into one buffer). Receive-buffer overflow at
any of the three list sites increments `QUIC_MIB_FRM_RCVBUFDROP`
(inqueue.c:252, 502, 652).

Receive flow-control *advance* (as opposed to enforcement) is
`quic_inq_flow_control()` (inqueue.c:52): after the app reads data, it bumps the
connection and per-stream windows and sends MAX_DATA / MAX_STREAM_DATA (via
`quic_outq_transmit_frame`, inqueue.c:77, 101) when consumed headroom drops below
1/16 of the window; under memory pressure it halves the window first.

## Send path (outqueue.c)

Five lists in `struct quic_outqueue` (init `quic_outq_init`, outqueue.c:1386):
`control_list` (ACK, MAX_DATA, PATH_CHALLENGE, CONNECTION_CLOSE, …, priority-
ordered), `stream_list` (STREAM frames), `datagram_list`, `transmitted_list`
(frames packed into a packet and tracked for possible retransmission), and
`packet_sent_list` (per-packet-number records holding frame-pointer arrays, for
ACK/loss processing).

- Pump: `quic_outq_transmit()` (outqueue.c:334) drains control frames at Initial,
  then Handshake, then App level (`quic_outq_transmit_ctrl`, outqueue.c:70), then
  datagrams (outqueue.c:147), then stream data (`quic_outq_transmit_stream`,
  outqueue.c:256), flushing the final partial packet. Each loop appends frames to
  the in-progress packet (`quic_packet_tail`) subject to crypto readiness and the
  congestion/anti-amplification check (`quic_outq_limit_check`), flushing a full
  packet via `quic_packet_create_and_xmit`.
- Enqueue: `quic_outq_stream_tail()` (outqueue.c:450) drives `send.state`
  READY->SEND->SENT, charges socket memory, and appends; `quic_outq_stream_append()`
  (outqueue.c:400) coalesces onto the last not-yet-transmitted stream frame;
  `quic_outq_ctrl_tail()` (outqueue.c:518) inserts control frames in priority
  order (level, then frame priority); `quic_outq_dgram_tail()` (outqueue.c:493).
  `quic_outq_transmit_frame()` (outqueue.c:1271) is the generic single-frame
  helper used everywhere (MAX_DATA, *_BLOCKED, PING, CONNECTION_CLOSE).

Loss recovery (RFC 9002):

- `quic_outq_transmitted_sack()` (outqueue.c:769) is OnAckReceived: it walks
  `packet_sent_list` for the acked range, decrements inflight, frees the acked
  frames (`quic_outq_psent_sack_frames`, outqueue.c:697 — idempotent against
  frames already acked by another packet), updates RTT from the packet matching
  `ack_largest` (`quic_cong_rtt_update`), and drives congestion control
  (`on_packet_acked`, `on_ack_recv`).
- `quic_outq_retransmit_mark()` (outqueue.c:1067) is DetectAndRemoveLostPackets:
  a sent packet is lost if its number is `<= max_pn_acked_seen` AND it is either
  `QUIC_KPACKET_THRESHOLD` (=3) packets behind the highest acked (packet
  threshold) or older than `loss_delay` (time threshold) — RFC 9002 §6.1, quoted
  outqueue.c:1085-1095; otherwise it arms `space->loss_time`. Lost frames are
  requeued (`quic_outq_psent_retransmit_frames`, outqueue.c:1030 ->
  `quic_outq_retransmit_frame`, outqueue.c:987), incrementing
  `QUIC_MIB_FRM_RETRANS` (outqueue.c:1024); non-retransmittable frames (ACK,
  PADDING) are dropped.
- `quic_outq_update_loss_timer()` (outqueue.c:940) is SetLossDetectionTimer:
  earlier of the min loss_time across spaces or the PTO
  (`cong->pto * 2^pto_count`, plus an App-level `max_ack_delay` term).
- `quic_outq_transmit_pto()` (outqueue.c:1163) is OnLossDetectionTimeout: marks
  loss or sends a single ack-eliciting probe (falling back to a bare PING),
  bumping `pto_count` (capped at `QUIC_MAX_PTO_COUNT = 8`).

Send flow control: `quic_outq_flow_control()` (outqueue.c:179) checks connection
then stream send limits and emits DATA_BLOCKED / STREAM_DATA_BLOCKED (once per
limit-update cycle) when `sndblock` is set; `quic_outq_wspace()` (outqueue.c:236)
reports writable bytes = min(socket wspace, connection headroom, stream headroom).

Connection close: `quic_outq_transmit_close()` (outqueue.c:647) is the abrupt
error path — sends a transport CONNECTION_CLOSE and forces state CLOSED;
`quic_outq_transmit_app_close()` (outqueue.c:669) is the graceful app path —
sends CONNECTION_CLOSE at the handshake level if still handshaking, else sets
`close_pending`, flushes pending data, and sends CONNECTION_CLOSE_APP at App
level. `close_errcode`/`close_frame` are set only in the former; `close_phrase`
is populated elsewhere (socket.c — not confirmed in outqueue.c).

## Fuzzing relevance

The receive flow-control and final-size checks (inqueue.c) are the STREAM-frame
protocol-violation gates most reachable with real data: a mutated STREAM frame
with an offset past the advertised limit, or a changed final size after FIN, lands
on `FLOW_CONTROL` / `FINAL_SIZE` here (see `04_frame.md` for the frame-parse-side
checks). The reassembly lists are a stateful surface — out-of-order delivery
across many offsets exercises the insertion/splice logic and the OOO buffer limit
(`FRM_RCVBUFDROP`). The loss-recovery machinery is driven by crafted ACK frames
(ack ranges, ECN counts) against the sent-packet list.

## Cross-references

- The frame parse side (STREAM/ACK/RESET_STREAM/MAX_* validation): `04_frame.md`.
- Packets the pump builds and the ACK/loss metadata: `03_packet.md`.
- Congestion control the ack/loss paths drive: `08_congestion.md`.
- Timers (loss, SACK/idle, pace) that fire these paths: `07_path.md`.
- Receive-buffer and retransmit counters: `10_mib.md`.
