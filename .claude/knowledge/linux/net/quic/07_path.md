# Paths: validation, migration, anti-amplification, PMTU, timers

How QUIC handles the network path underneath a connection: detecting an address
change, validating a new path with PATH_CHALLENGE/RESPONSE entropy, migrating to
it, the anti-amplification limit that bounds what a server sends to an unvalidated
address, PLPMTUD, and the timers that drive all of it. Because a QUIC connection
is keyed on a connection ID (`06_connid.md`), not the 4-tuple, it can move between
paths; this doc is that machinery.

Spec: RFC 9000 §8 (address validation / anti-amplification), §8.2 (path
validation), §9 (connection migration), RFC 8899 (PLPMTUD), RFC 9002 (timers).
Code: `net/quic/path.c`, `net/quic/timer.c`, headers `path.h`, `timer.h`; the
PATH_CHALLENGE/RESPONSE frames are in `net/quic/frame.c` (`04_frame.md`); the
anti-amplification accounting is split into `outqueue.c`/`packet.c`.

## The path group

`struct quic_path_group` (path.h:70-112) holds two `quic_path` slots: `path[0]` is
active, `path[1]` is the alternate/candidate. Each `quic_path` (path.h:59) has its
source/dest addresses and a bound UDP tunnel socket. The group also holds the
handshake CID-validation anchors (`orig_dcid`, `retry_dcid`), the 8-byte
PATH_CHALLENGE `entropy`, a `path_seq` seqcount guarding `path[0]` during a swap,
the anti-amplification counters, the PLPMTUD `pl` sub-struct, and the migration
`alt_state`.

`quic_path_init()` (path.c:586) just inits the seqcount. Binding a UDP tunnel
socket per path is `quic_path_bind()` (path.c:166): it reuses an existing
`quic_udp_sock` for an (addr,port) or creates one (`quic_udp_sock_create`), with
privileged-port and ephemeral-port-rover handling like `inet_bind`.
`quic_path_unbind()` (path.c:289) drops the socket and resets the alt state.

## Path validation: PATH_CHALLENGE / PATH_RESPONSE

Path validation proves the peer is reachable at a new address and is not an
off-path attacker replaying packets. It uses 8 bytes of random entropy
(`QUIC_PATH_ENTROPY_LEN`, path.h:17):

- We send a challenge: `quic_frame_path_challenge_create` (frame.c ~586) fills
  `paths->entropy` with `get_random_bytes()` and emits PATH_CHALLENGE.
- Peer's PATH_CHALLENGE (RX): `quic_frame_path_challenge_process` (frame.c:1520)
  echoes the received 8 bytes back in a PATH_RESPONSE (RFC 9000 §19.17).
- Peer's PATH_RESPONSE (RX): `quic_frame_path_response_process` (frame.c:2087)
  compares the echoed entropy against `paths->entropy` with `crypto_memneq`; a
  mismatch is **silently dropped** (not an error), a match drives migration
  promotion — if `alt_state == QUIC_PATH_ALT_PROBING` it unhashes the sock and
  calls `quic_path_swap()`.

Note: the `validated` flag (path.h:101) is set in protocol.c (:112/:123) and
packet.c (:1726), *not* in the PATH_RESPONSE handler — the entropy match drives the
path *swap*, while `validated` (which gates anti-amplification, below) is set
elsewhere. Verify the exact `validated` trigger at those sites if it matters.

## Migration state machine

`alt_state` (path.h:43-48, diagram at path.h:23-42):
`NONE -> PENDING -> PROBING -> SWAPPED`.

- A new/migrating path is detected on RX by `quic_path_detect_alt()`
  (path.c:312): it compares the incoming addresses against the active path, and —
  unless the corresponding `disable_saddr_alt`/`disable_daddr_alt` is set — records
  the candidate into `path[1]`, returning true only once the candidate has
  stabilized across two observations.
- `quic_outq_probe_path_alt()` (outqueue.c:1210) starts probing: if no alternate
  DCID is available it sets `alt_state = PENDING` (outqueue.c:1229, must first
  retire the old CID and get a new one); once an alt CID is selected
  (`quic_conn_id_select_alt`) it sets `alt_state = PROBING` (outqueue.c:1234) and
  begins PATH_CHALLENGE probing.
- A valid PATH_RESPONSE in PROBING triggers `quic_path_swap()` (path.c:258):
  it sets `alt_state = SWAPPED` and, under `local_bh_disable()` +
  `write_seqcount_begin(&paths->path_seq)`, promotes `path[1]` to `path[0]` (full
  struct swap if the alt has its own bound socket, else just the dest address).
  The seqcount lets lock-free RX readers in `quic_sock_lookup()` detect a torn
  read of `path[0]` during the swap.
- The path timer gives up after `QUIC_MAX_ALT_PROBES` (=3) failed challenges and
  unbinds the alt path (timer.c:107).

`disable_active_migration` is exposed per direction: `disable_saddr_alt` is the
peer's parameter (restricting migration of our source address),
`disable_daddr_alt` ours; both are read/written by
`quic_path_get_param`/`set_param` (path.c:337-355) and consumed in
`quic_path_detect_alt()` to suppress detection on that side.

## Anti-amplification limit

RFC 9000 §8 caps what a server sends to an unvalidated address at 3x what it has
received, to stop the server being used as a reflection amplifier. **This is not
in path.c** — path.c only declares the fields. Enforcement:

- TX gate: `outqueue.c:38-45` — for a server with `!paths->validated`, if
  `ampl_sndlen + (this packet) > ampl_rcvlen * 3` it sets `paths->blocked = 1` and
  refuses to send more (the literal 3x rule).
- Accounting: `packet.c` increments `ampl_rcvlen` as datagrams are received
  (packet.c:1601, 1715, 1908) and `ampl_sndlen` as packets are sent
  (packet.c:2249).
- Unblock: once more receive credit exists, packet.c:1786-1793 clears
  `paths->blocked` and re-arms the loss timer to resume sending.

So path.c defines the counters, outqueue.c gates on them, packet.c maintains them.

## PLPMTUD (RFC 8899)

Datagram Packetization Layer Path MTU Discovery, entirely in path.c with a local
state enum `{DISABLED, BASE, SEARCH, COMPLETE, ERROR}` (path.c:358) and its own
constants (`QUIC_BASE_PLPMTU 1200`, `QUIC_MAX_PLPMTU 9000`, `QUIC_MIN_PLPMTU 512`,
`QUIC_MAX_PROBES 3`, step sizes; path.c:366-373). Note the base value 1200 here is
a *separate* macro from `QUIC_PATH_MIN_PMTU 1200U` in path.h:11 — same number,
different constants, don't merge them.

- `quic_path_pl_send()` (path.c:385): called after sending a probe; counts probes
  against `QUIC_MAX_PROBES` and handles failure transitions (BASE->ERROR,
  SEARCH black-hole->BASE, COMPLETE black-hole->BASE).
- `quic_path_pl_recv()` (path.c:443): on probe ack, grows the probe size (big step
  in BASE/ERROR->SEARCH, min step bisection in SEARCH until SEARCH->COMPLETE), and
  ages COMPLETE->SEARCH after a raise timer (`QUIC_PMTUD_RAISE_TIMER_FACTOR` = 30,
  path.h:19).
- `quic_path_pl_toobig()` (path.c:508): ICMP "packet too big" handler.
- `quic_path_pl_confirm()` (path.c:579): true if the probe's packet number falls in
  an acked range. `quic_path_pl_reset()` (path.c:562) resets to BASE.

## Timers (timer.c)

Five timers (`enum`, timer.h:11-19), with `QUIC_TIMER_IDLE` aliased to
`QUIC_TIMER_SACK`. All but PACE use `timer_list`; PACE uses an `hrtimer` for
precise pacing. A shared dispatch (`quic_timer_timeout`, timer.c:15) takes the
sock lock and, if the socket is owned by userspace, defers the handler via a
`sk_tsq_flags` bit instead of running it inline.

| timer | handler (timer.c) | what it does |
|-------|-------------------|--------------|
| LOSS | `quic_timer_loss_handler` (:72) | PTO-driven retransmission (`quic_outq_transmit_pto`) |
| SACK / IDLE | `quic_timer_sack_handler` (:34) | if `sack_flag == NONE` this is the idle timeout -> CONNECTION_CLOSE event + state CLOSED; else flush delayed ACK / queued frames and re-arm as idle timer |
| PATH | `quic_timer_path_handler` (:88) | retransmit PATH_CHALLENGE while probing (up to 3), then give up + unbind alt; send keepalive PING; re-arm at `keepalive_interval` |
| PMTU | `quic_timer_pmtu_handler` (:126) | re-send a PLPMTUD probe (`quic_outq_transmit_probe`) |
| PACE | `quic_timer_pace_handler` (:140) | flush pending frames once pacing delay elapses (hrtimer) |

Minimum/default timeouts are in timer.h:28-33 (`QUIC_MIN_IDLE_TIMEOUT 1s`,
`QUIC_DEF_IDLE_TIMEOUT 30s`, `QUIC_MIN_PATH_TIMEOUT 1.5s`, etc.).

## Fuzzing relevance

Path validation and migration are a stateful surface reachable once a connection
is established: a changed source address triggers `detect_alt` and the
PATH_CHALLENGE/RESPONSE exchange, and the swap path (with its seqcount) is
concurrency-sensitive. The anti-amplification limit is a server-side send gate
driven by the receive/send byte accounting — crafted small receives vs large sends
exercise the 3x boundary. PATH_RESPONSE entropy mismatch is silently dropped, so
it is the migration *promotion* (entropy match + PROBING state) that is the
interesting edge. The idle timer firing (SACK handler with `sack_flag == NONE`) is
the connection-teardown path.

## Cross-references

- Connection IDs that migration consumes (alt CID selection): `06_connid.md`.
- PATH_CHALLENGE/RESPONSE frame validation and entropy handling: `04_frame.md`.
- Where PMTU feeds packet sizing and MSS: `03_packet.md`.
- Loss/PTO timers and the send pump they drive: `05_streams.md`, `08_congestion.md`.
