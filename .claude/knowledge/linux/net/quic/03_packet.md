# Packets: headers, packet-number spaces, RX/TX machinery

How a QUIC packet is parsed on the way in and assembled on the way out: the two
header forms, the long-header packet types and how they map to crypto levels, the
three packet-number spaces, packet-number encode/decode, and the send-side
bundling. This is the layer between the UDP tunnel (`01_overview.md`) and frame
processing (`04_frame.md`); it is also where almost all the drop counters fire
(`10_mib.md`).

Spec: RFC 9000 §12, §17 (packet formats), Appendix A (PN decoding), RFC 9369
(QUIC v2), RFC 9368 (compatible version negotiation).
Code: `net/quic/packet.c`, `net/quic/pnspace.c`, headers `packet.h`, `pnspace.h`,
bitfields and varint helpers in `common.h`/`common.c`.

## Two header forms

The first byte's top bits say which form. `common.h` defines both as bitfields:

- **Short header** `struct quichdr` (common.h:80-96): `form:1, fixed:1, spin:1,
  reserved:2, key:1, pnl:2`. Used for 1-RTT (App) packets after the handshake.
  The `key` bit is the key-phase; `pnl` is packet-number length minus 1.
- **Long header** `struct quichshdr` (common.h:103-117): `form:1, fixed:1,
  type:2, reserved:2, pnl:2`. Used for Initial / 0-RTT / Handshake / Retry during
  setup, and carries explicit version, DCID, and SCID.

`quic_hdr(skb)` / `quic_hshdr(skb)` (common.h:98, 119) cast `skb->data`. The form
bit is tested at e.g. packet.c:537, 943, 1591, 2158
(`QUIC_PACKET_FORM_SHORT = 0`, `..._LONG = 1`, packet.h:77-78).

## RX entry and dispatch

The UDP tunnel delivers to `quic_packet_rcv()` (packet.c:596), which looks up the
owning socket (`quic_packet_get_sock`, packet.c:522 — short-header fast-path DCID
lookup at packet.c:544, long-header DCID parse + lookup at packet.c:569) and then
either processes immediately (fast path, socket not owned:
`QUIC_MIB_PKT_RCVFASTPATHS`, packet.c:628) or defers to the socket backlog
(`QUIC_MIB_PKT_RCVBACKLOGS`, packet.c:625).

`quic_packet_process()` (packet.c:2148) is the per-socket entry and dispatches on
state and form:

- closed socket -> drop (packet.c:2150);
- listening socket -> `quic_packet_listen_process()` (packet.c:927) — the
  server's first-contact path (Retry, version negotiation, token checks, request
  sock creation);
- long header -> `quic_packet_handshake_process()` (packet.c:1562), which loops
  over coalesced long-header packets in one datagram (`while (skb->len > 0)`,
  packet.c:1590) and recurses into `quic_packet_process` for a trailing
  short-header packet (packet.c:1608);
- short header -> `quic_packet_app_process()` (packet.c:1979) — decrypt,
  PN-check, frame-process, PN-mark.

For each packet: decrypt (`quic_crypto_decrypt`, packet.c:1631 handshake / 2057
app), then `quic_pnspace_check` (duplicate/old), then `quic_frame_process`
(packet.c:1680 / 2122), then `quic_pnspace_mark`. Async crypto completion
re-enters via `quic_packet_decrypt_done` (packet.c:1372).

## Long-header types, per version, and crypto levels

The on-wire two-bit type value differs between v1 and v2 (packet.h:53-68):

| internal | v1 value | v2 value | crypto level |
|----------|----------|----------|--------------|
| INITIAL | 0 | 1 | QUIC_CRYPTO_INITIAL |
| 0RTT | 1 | 2 | QUIC_CRYPTO_EARLY |
| HANDSHAKE | 2 | 3 | QUIC_CRYPTO_HANDSHAKE |
| RETRY | 3 | 0 | (not a crypto level) |

`quic_packet_version_get_type()` (packet.c:45) maps on-wire->internal on RX,
`..._put_type()` (packet.c:65) the reverse on TX. The type->level mapping and the
"not ready yet -> backlog" gating happen in
`quic_packet_handshake_header_process()` (packet.c:1503-1548): Handshake/0-RTT
packets whose crypto `recv_ready` is not yet set are queued to the backlog
(packet.c:1523-1537) rather than dropped. `enum quic_crypto_level`
(uapi quic.h:48-53): APP=0, INITIAL=1, HANDSHAKE=2, EARLY=3.

## Version negotiation and Retry

- Supported versions: `quic_versions[][4]` (packet.c:27) — v1 and v2 plus their
  compatible lists; `quic_packet_compatible_versions()` (packet.c:34),
  `quic_packet_select_version()` (compatible VN per RFC 9368, packet.c:170).
- A listening server that gets an unsupported version (packet.c:1001) emits a
  Version Negotiation packet (version field 0) via
  `quic_packet_version_create_and_xmit()` (packet.c:757). A client processes a
  received VN in `quic_packet_version_process()` (packet.c:1279).
- **Retry** (address validation): server generates with
  `quic_packet_retry_create_and_xmit()` (packet.c:661), triggered from the listen
  path when there is no token (packet.c:1079) or a bad token (packet.c:1094). The
  client validates the Retry integrity tag
  (`quic_crypto_get_retry_tag` + `crypto_memneq`, packet.c:1227) in
  `quic_packet_retry_process()` (packet.c:1179), updating `paths->orig_dcid` /
  `paths->retry_dcid` and setting `paths->retry = 1` (packet.c:1249-1259).

## Stateless reset

On RX, a short-header packet whose DCID matches no connection (`cb->seqno == -1`,
packet.c:2020) is checked for a stateless-reset token via
`quic_packet_stateless_reset_process()` (packet.c:1134), comparing against stored
dest-CID tokens (`quic_conn_id_token_exists`, packet.c:1159; see `06_connid.md`).
On the server side, an unrecognized packet can trigger emission of a stateless
reset via `quic_packet_stateless_reset_create_and_xmit()` (packet.c:828), from the
listen path (packet.c:966, 1017).

## Packet-number encode/decode

- **Decode** (truncated-PN reconstruction, RFC 9000 Appendix A):
  `quic_get_num(max_pkt_num, pkt_num, n)` (common.c:379) runs the candidate-window
  algorithm, called from `quic_crypto_get_number()` (crypto.c:297) after header
  protection is removed, seeded with `cb->number = space->max_pn_seen`
  (packet.c:1629 / 2055).
- **Encode**: this implementation always writes a **full 4-byte** packet number
  (`QUIC_PACKET_NUMBER_LEN = QUIC_PN_MAX_LEN = 4`), never truncating to save bytes
  — `cb->number_len` is set to 4 at packet.c:2204 and `pnl` is hardcoded to 3
  (long: packet.c:2453, short: packet.c:2592). Worth knowing if you are checking a
  harness's on-wire PN length.
- Constants (common.h:24-26): `QUIC_PN_MAX_LEN 4`, `QUIC_PN_BITS 62`,
  `QUIC_PN_MAX = 2^62-1`.

## Packet-number spaces (pnspace.c)

Three spaces, `QUIC_PNSPACE_MAX = QUIC_CRYPTO_MAX - 1 = 3` (pnspace.h:18). The
level->space map is `space[level % QUIC_CRYPTO_EARLY]` (socket.h:176), so
**0-RTT and 1-RTT (App) share one space** (index 0); Initial=1, Handshake=2. Each
`struct quic_pnspace` (pnspace.h:62) holds a received-PN bitmap (`pn_map`), the
base/min/max tracking for ACK generation, ECN counters, and loss/inflight state.

- `quic_pnspace_check(space, pn)` (pnspace.c:73): returns `-EINVAL` if `pn` is out
  of `[0, QUIC_PN_MAX]` (pnspace.c:75) or older than `min_pn_seen`
  (pnspace.c:81); `1` if already received (below `base_pn`, pnspace.c:84, or bit
  set, pnspace.c:86); `0` if genuinely new or first. Callers treat `>0` as
  "duplicate, ack but do not reprocess" (packet.c:1663, 2099) and `<0` as drop +
  `QUIC_MIB_PKT_INVNUMDROP`.
- `quic_pnspace_mark(space, pn, gfp)` (pnspace.c:116): records a received PN,
  seeding `base_pn = pn+1` on the first, growing the bitmap
  (`quic_pnspace_grow`, pnspace.c:45) as needed, advancing `base_pn` past
  contiguous runs (`quic_pnspace_move`, pnspace.c:97), and periodically shifting
  the window based on time (`max_time_limit`) or fill (`QUIC_PN_MAP_LIMIT`).
- `quic_pnspace_num_gabs(space, gabs)` (pnspace.c:232): builds the SACK gap-ack
  blocks for ACK-frame generation, capped at `QUIC_PN_MAP_MAX_GABS = 32`
  (pnspace.h:11), merging overflow.
- `quic_pnspace_init/free` (pnspace.c:18, 32). Bitmap sizing: initial 64 bits,
  grows to `QUIC_PN_MAP_SIZE = 4096`, limit `3072` (pnspace.h:13-16). (pnspace.c
  has no MIB increments.)

ECN accounting and validation (the `ecn_count[dir][codepoint]` arrays and the
RFC 9000 §13.4.2.1 validation) live as inline helpers in pnspace.h:115-193.

## Send side

- `quic_packet_config()` (packet.c:2684) sets level, computes overhead, reserves
  taglen, and routes. `quic_packet_overhead()` (packet.c:2658): header byte + PN
  length + DCID, plus (non-App) SCID, Initial token, version, and length fields.
- `quic_packet_route()` (packet.c:2630) resolves the route, sets `hlen`, clamps
  PMTU to `[QUIC_PATH_MIN_PMTU 1200, QUIC_PATH_MAX_PMTU]`, and updates MSS
  (`quic_packet_mss_update`, packet.c:2605, which also feeds `quic_cong_set_mss`).
- `quic_packet_tail()` (packet.c:2897) appends one frame to the in-progress
  packet if level/path match, enforcing MSS (falling back to `ipfragok` when a
  single frame exceeds MSS on an empty packet).
- `quic_packet_create_and_xmit()` (packet.c:2853): checks the PN, builds via
  `quic_packet_handshake_create()` (long, packet.c:2378) or
  `quic_packet_app_create()` (short, packet.c:2533), then `quic_packet_xmit()`.
  Frame bytes + padding are written in `quic_packet_pack_frames()` (packet.c:2186,
  which records the sent-packet metadata for ACK/loss tracking). Multiple QUIC
  packets can be coalesced into one UDP datagram by `quic_packet_bundle()`
  (packet.c:2772), which flushes immediately after a short-header packet (nothing
  may follow it, RFC 9000 §12.2). Final send: `quic_packet_flush()`
  (packet.c:2883) -> `quic_lower_xmit()`.
- Protection runs inline: `quic_packet_xmit()` calls `quic_crypto_encrypt()`
  unless the form's taglen is 0 (the disable_1rtt path, packet.c:2825; see `02`),
  counting ENC fast-path / backlog / drop (packet.c:2836-2844).

## The drop/fast-path/backlog counters

Nearly every malformed-header rejection increments `QUIC_MIB_PKT_INVHDRDROP`
(11 sites: packet.c:951, 975, 997, 1025, 1032, 1048, 1056, 1618, 1650, 2009,
2086 — e.g. short packet too small for its DCID, bad long-header parse, server VN
with version 0, DCID shorter than the default length, token parse failure, ALPN
demux failure, reserved bits non-zero after decrypt, App `fixed` bit clear
without grease). PN-window failures are `INVNUMDROP` (packet.c:1669, 2105); a
frame that fails processing is `INVFRMDROP` (packet.c:1682, 2124); AEAD failure is
`DECDROP` (packet.c:424, 1377, 1637, 2067). The full list with meanings is in
`10_mib.md`.

## Fuzzing relevance

The packet layer is the first thing a raw mutated UDP payload hits, so the
header-parse checks (INVHDRDROP) are reachable blind. An Initial packet can even
be decrypted blind (its keys derive from the DCID on the wire, `02`), so Initial
frame processing is reachable without any handshake. The INVHDRDROP / INVNUMDROP
/ INVFRMDROP / DECDROP split is the cheap oracle for which stage a mutation hit.
Coalesced long-header packets, version negotiation, and the Retry path are all
driven from one datagram, so a single crafted datagram can exercise several of
these branches.

## Cross-references

- Keys and the decrypt/encrypt internals: `02_handshake_crypto.md`.
- What `quic_frame_process` does with a decrypted packet's frames: `04_frame.md`.
- Connection-ID lookup and stateless-reset tokens: `06_connid.md`.
- Path/PMTU that `quic_packet_route` reads: `07_path.md`. Counters: `10_mib.md`.
