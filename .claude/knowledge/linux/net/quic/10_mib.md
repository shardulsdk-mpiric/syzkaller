# QUIC SNMP/MIB counters (/proc/net/quic/snmp)

The QUIC MIB is a small per-netns SNMP counter set, the QUIC analogue of
`/proc/net/snmp`'s TCP line. For a fuzzer or a test harness it is the cheapest
executor-independent signal that a given code path ran: most of the counters are
drop/error counters, so watching them tells you *which rejection path* a mutated
packet hit without reading a crash. This doc lists every counter, its exact
increment site(s) in the tree, and the condition that drives it.

Code: enum in `net/quic/protocol.h`, the SNMP name table + proc dump in
`net/quic/protocol.c`, increment macros in `net/quic/protocol.h`.

## The enum and the macros

`enum { QUIC_MIB_* }` is defined at `protocol.h:21-43`. `QUIC_MIB_NUM = 0` is a
spare slot-0; `QUIC_MIB_MAX` bounds the array. The per-net storage is
`struct quic_mib { unsigned long mibs[QUIC_MIB_MAX]; }` (`protocol.h:45-47`),
held in `struct quic_net` via `DEFINE_SNMP_STAT` (`protocol.h:49-54`).

Two macros wrap access (`protocol.h:58-59`):

```c
#define QUIC_INC_STATS(net, field) SNMP_INC_STATS(quic_net(net)->stat, field)
#define QUIC_DEC_STATS(net, field) SNMP_DEC_STATS(quic_net(net)->stat, field)
```

Only `QUIC_MIB_CONN_CURRENTESTABS` is ever decremented (it is a gauge, not a
monotonic counter); every other counter is increment-only.

## How it surfaces: /proc/net/quic/snmp

`quic_net_proc_init()` (`protocol.c:441`) creates a per-netns `quic/` directory
under `/proc/net/` and registers three files (`protocol.c:443-456`):

| proc file | shows |
|-----------|-------|
| `/proc/net/quic/snmp` | the MIB counters (this doc), via `quic_snmp_seq_show` (`protocol.c:409`) |
| `/proc/net/quic/conns` | one line per established QUIC sock (`quic_conns_seq_show`, `protocol.c:265`) |
| `/proc/net/quic/eps`   | one line per listening/bound endpoint (`quic_eps_seq_show`, `protocol.c:331`) |

The counter *names* printed in `snmp` come from `quic_snmp_list[]`
(`protocol.c:387-407`), an array of `SNMP_MIB_ITEM(name, enum)`. `snmp` prints
`name\tvalue` for each, summed across CPUs with
`snmp_get_cpu_field_batch_cnt()` (`protocol.c:418-422`). The whole proc layer is
under `#if IS_ENABLED(CONFIG_PROC_FS)`.

## The counters, with exact increment sites

The `/proc` name is the `SNMP_MIB_ITEM` string; the enum is what the code uses.

### Connection gauges/counters

| /proc name | enum | Meaning | Site(s) |
|------------|------|---------|---------|
| QuicConnCurrentEstabs | QUIC_MIB_CONN_CURRENTESTABS | Currently-established connections (gauge: inc on enter ESTABLISHED, dec on leave) | inc `socket.h:238`, dec `socket.h:240` (both in `quic_set_state`) |
| QuicConnPassiveEstabs | QUIC_MIB_CONN_PASSIVEESTABS | Server-side (passive) connections established | `socket.h:235` (in `quic_set_state`, when `quic_is_serv`) |
| QuicConnActiveEstabs | QUIC_MIB_CONN_ACTIVEESTABS | Client-side (active) connections established | `socket.h:236` (in `quic_set_state`, when not serv) |

`quic_set_state()` (`socket.h:226`) is the single chokepoint: on the transition
*into* `QUIC_SS_ESTABLISHED` it bumps CURRENTESTABS plus one of PASSIVE/ACTIVE
depending on `quic_is_serv(sk)` (which is "has a non-zero `sk_max_ack_backlog`",
`socket.h:166`); on the transition *out of* ESTABLISHED it decrements
CURRENTESTABS.

### Packet fast-path / backlog accounting

These distinguish how a packet was processed. "Fast path" = crypto done inline
in softirq/process context; "backlog" = deferred because keys were not yet
installed or the socket was owned.

| /proc name | enum | Meaning | Site(s) |
|------------|------|---------|---------|
| QuicPktRcvFastpaths | QUIC_MIB_PKT_RCVFASTPATHS | Packet received and handled on the fast path | `packet.c:628` |
| QuicPktDecFastpaths | QUIC_MIB_PKT_DECFASTPATHS | Packet decrypted on the fast path | `packet.c:427`, `packet.c:1641`, `packet.c:2077` |
| QuicPktEncFastpaths | QUIC_MIB_PKT_ENCFASTPATHS | Packet encrypted on the fast path | `packet.c:2844` |
| QuicPktRcvBacklogs | QUIC_MIB_PKT_RCVBACKLOGS | Packet processed via the backlog list | `packet.c:625` |
| QuicPktDecBacklogs | QUIC_MIB_PKT_DECBACKLOGS | Packet decrypted in the backlog | `packet.c:1634`, `packet.c:2060` |
| QuicPktEncBacklogs | QUIC_MIB_PKT_ENCBACKLOGS | Packet encrypted in the backlog | `packet.c:2840` |

### Packet drop counters (the fuzzing signal)

| /proc name | enum | Meaning | Site(s) |
|------------|------|---------|---------|
| QuicPktInvHdrDrop | QUIC_MIB_PKT_INVHDRDROP | Dropped: invalid/unparseable packet header | `packet.c:951,975,997,1025,1032,1048,1056,1618,1650,2009,2086` |
| QuicPktInvNumDrop | QUIC_MIB_PKT_INVNUMDROP | Dropped: invalid packet number (duplicate / out of window) | `packet.c:1669`, `packet.c:2105` |
| QuicPktInvFrmDrop | QUIC_MIB_PKT_INVFRMDROP | Dropped: a frame in the packet failed processing | `packet.c:1682`, `packet.c:2124` |
| QuicPktRcvDrop | QUIC_MIB_PKT_RCVDROP | Dropped on receive (general: routing/addr/alloc) | `packet.c:355`, `packet.c:1446`, `socket.c:86`, `socket.c:139` |
| QuicPktDecDrop | QUIC_MIB_PKT_DECDROP | Dropped: AEAD decryption failed | `packet.c:424`, `packet.c:1377`, `packet.c:1637`, `packet.c:2067` |
| QuicPktEncDrop | QUIC_MIB_PKT_ENCDROP | Dropped: encryption failed on the send side | `packet.c:2748`, `packet.c:2836` |

INVHDRDROP has by far the most sites: nearly every malformed long/short-header
field, bad version, bad CID length, or coalesced-packet parse failure in the RX
path routes here (see `03_packet.md` for which header check is which line).
INVFRMDROP is driven by a non-zero `QUIC_SKB_CB(skb)->errcode` after the frame
loop (frame-level protocol violations are enumerated in `04_frame.md`).

### Frame counters

| /proc name | enum | Meaning | Site(s) |
|------------|------|---------|---------|
| QuicFrmRcvBufDrop | QUIC_MIB_FRM_RCVBUFDROP | Frame dropped: receive buffer / memory limit hit | `inqueue.c:252,502,652` |
| QuicFrmRetrans | QUIC_MIB_FRM_RETRANS | Frame retransmitted (loss recovery) | `outqueue.c:1024` |
| QuicFrmOutCloses | QUIC_MIB_FRM_OUTCLOSES | CONNECTION_CLOSE frame sent | `frame.c:858` (in the CONNECTION_CLOSE create path) |
| QuicFrmInCloses | QUIC_MIB_FRM_INCLOSES | CONNECTION_CLOSE frame received | `frame.c:1900` (in the CONNECTION_CLOSE process path) |

## Notes for a harness

- The counters are per network namespace (`quic_net(net)->stat`). The executor
  unshares the net namespace, so read `/proc/net/quic/snmp` from *inside* the
  worker's netns, not the root ns, or you will read zeroes. (This mirrors the
  MPTCP MIB-verify gotcha.)
- The drop counters are the clean "which rejection fired" oracle: send a mutated
  packet, diff the snmp file, and the delta names the gate. INVHDRDROP vs
  INVNUMDROP vs INVFRMDROP vs DECDROP cleanly separate header-parse, PN-window,
  frame-validation, and AEAD failures.
- There is no counter for most *successful* frame processing; success is only
  visible via the fast-path/backlog counters and the data actually delivered.

## Cross-references

- The packet-RX header checks behind each INVHDRDROP/INVNUMDROP: `03_packet.md`.
- The frame-level protocol violations behind INVFRMDROP: `04_frame.md`.
- Decryption behind DECDROP/ENCDROP: `02_handshake_crypto.md`.
- Where files live: `09_code_map.md`.
