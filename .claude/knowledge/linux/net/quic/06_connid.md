# Connection IDs and stateless reset

How QUIC identifies a connection independent of the 4-tuple, how the two
connection-ID sets (ours = source, peer's = dest) are managed, how NEW/RETIRE
rotate them, and how stateless reset uses the per-dest-CID token. Connection IDs
are what make migration (`07_path.md`) possible: the connection survives an
address change because it is keyed on a CID, not on IP:port.

Spec: RFC 9000 §5.1 (connection IDs), §5.1.1 (issuing/retiring),
§10.3 (stateless reset), §18.2 (active_connection_id_limit).
Code: `net/quic/connid.c`, `net/quic/connid.h`; the NEW/RETIRE frame parsing is in
`net/quic/frame.c` (see `04_frame.md`).

## The two sets and the data structures

Each `quic_sock` holds two `quic_conn_id_set`s (socket.h:98-99): `source`
(the CIDs *we* issued, that the peer puts in the DCID field of packets to us) and
`dest` (the CIDs the *peer* issued, that we put in the DCID of packets to them).
`struct quic_conn_id_set` (connid.h:38-47): an ordered `head` list of entries, an
`active` pointer (the CID in use on the current path), an `alt` pointer (the CID
reserved for a new/migrating path), `entry_size` (distinguishes source vs dest
entries), `max_count` (= the negotiated `active_connection_id_limit`), and
`count`.

Entries share `struct quic_common_conn_id` (connid.h:18-23: the `id` bytes, list
node, sequence `number`, `hashed` flag). Source entries
(`quic_source_conn_id`, connid.h:25-30) add an RCU hash node and the owning `sk`;
dest entries (`quic_dest_conn_id`, connid.h:32-36) add a 16-byte stateless-reset
`token`. Constants (connid.h:11-15): `QUIC_CONN_ID_LIMIT 8`, `QUIC_CONN_ID_DEF 7`,
`QUIC_CONN_ID_LEAST 2`, `QUIC_CONN_ID_TOKEN_LEN 16`, max CID length
`QUIC_CONN_ID_MAX_LEN 20` / default `QUIC_CONN_ID_DEF_LEN 8` (common.h:21-22).
(Where DEF/LIMIT/LEAST are consumed was not located in connid.c — likely the
sockopt / transport-param negotiation in socket.c; verify at the use site.)

## Source-CID hash: finding the socket on RX

Our source CIDs are registered in a global per-netns hash so the receive path can
find the owning socket from a packet's DCID. `quic_conn_id_add()` (connid.c:110)
inserts a CID keyed by sequence number into the ordered per-set list; for a source
CID it also marks it `hashed`, stores `sk`, and adds it to
`quic_source_conn_id_head()` under the bucket lock, after a collision check
against other sockets in the same net (connid.c:158-184). `quic_conn_id_lookup()`
(connid.c:23) is the RX lookup: an RCU walk of that hash matching net + exact CID
bytes, taking an `sk_refcnt` with `refcount_inc_not_zero` (connid.c:38) so the
socket cannot vanish mid-use. Removal (`quic_conn_id_remove()`, connid.c:206 ->
`quic_conn_id_del`/`quic_source_conn_id_free`, connid.c:80-105) unlinks under the
bucket lock and defers the `kfree` with `call_rcu`, so concurrent lookups never
UAF.

Note `quic_conn_id_find()` (connid.c:229) is different: it is an ordered-list scan
by sequence *number* within one socket's own set, used by the frame/handshake code
— not a cross-socket hash lookup.

## NEW_CONNECTION_ID and RETIRE_CONNECTION_ID

CID rotation is driven by frames; `connid.c` provides the set operations and
`frame.c` the wire handling (validation detailed in `04_frame.md`):

- We issue a new source CID: `quic_frame_new_conn_id_create` (frame.c ~500)
  generates a random CID at `last_number + 1` (`quic_conn_id_generate`,
  connid.h:66), derives its stateless-reset token with
  `quic_crypto_derive_secret(..., "stateless_reset", ...)`, and registers it via
  `quic_conn_id_add()`.
- We retire a peer CID: `quic_frame_retire_conn_id_create` builds the frame then
  calls `quic_conn_id_remove()` on the **dest** set.
- Peer's NEW_CONNECTION_ID (RX, `quic_frame_new_conn_id_process`, frame.c:1257):
  validates `retire_prior_to <= sequence` (FRAME_ENCODING) and that the resulting
  active count does not exceed `max_count` (CONNECTION_ID_LIMIT), then
  `quic_conn_id_add()` into the dest set. A new DCID arriving can unblock a pending
  migration (`quic_outq_probe_path_alt` when `alt_state == PENDING`,
  frame.c:1327).
- Peer's RETIRE_CONNECTION_ID (RX, `quic_frame_retire_conn_id_process`,
  frame.c:1351): bounds-checks the seqno against the source set (PROTOCOL_VIOLATION
  on out-of-range, or if the peer tries to retire the very CID the packet arrived
  on), then `quic_conn_id_remove()` on the source set.

`quic_conn_id_add()` keeps the list number-ordered and advances `count`/`active`
only across a contiguous run from `first` (connid.c:188-199). `active` can be
repointed with `quic_conn_id_update_active()` (connid.c:243). The alt-CID
selection logic for migration (`quic_conn_id_select_alt`, connid.h:75) lives in
the header and is used by the path code.

## Stateless reset

A stateless reset lets an endpoint that has lost all connection state tell the
peer to tear down, without keys. Each dest CID carries a 16-byte token
(`quic_dest_conn_id.token`, RFC 9000 §10.3), stored by `quic_conn_id_add()`
(connid.c:154) or `quic_conn_id_set_token()` (connid.h:154). On RX, an
otherwise-unmatched short-header packet is checked against these tokens by
`quic_conn_id_token_exists()` (connid.c:51), which compares with `crypto_memneq`
(constant-time) and skips all-zero (unset) tokens, checking the `active` CID first
then walking the set. This is called from the packet layer's stateless-reset path
(packet.c:1159; see `03_packet.md`). We derive the tokens for our *own* source
CIDs via `quic_crypto_derive_secret(..., "stateless_reset", ...)` (frame.c, see
above), so we can recognize a reset the peer echoes back.

## Fuzzing relevance

The source-CID hash is the RX demultiplex point, so a mutated DCID exercises the
lookup and the stateless-reset fallback. NEW/RETIRE_CONNECTION_ID frames are a
rich validation surface — `retire_prior_to` vs sequence ordering, the
active-CID-limit check (CONNECTION_ID_LIMIT), and the "retire the CID you arrived
on" PROTOCOL_VIOLATION are all exact, cheap-to-reach checks once a connection is
up (`04_frame.md`). The RCU + refcount discipline on the source-CID hash is the
concurrency-sensitive part worth exercising with concurrent add/remove/lookup.

## Cross-references

- The NEW/RETIRE frame validation sites (errcodes, file:line): `04_frame.md`.
- Where CIDs are looked up on RX and stateless reset is detected: `03_packet.md`.
- How alt CIDs drive migration: `07_path.md`.
- Stateless-reset-token derivation and crypto: `02_handshake_crypto.md`.
