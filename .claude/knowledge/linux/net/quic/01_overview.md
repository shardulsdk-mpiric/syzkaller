# QUIC in the Linux kernel: overview and the socket model

What this in-kernel QUIC is, how it is wired into the socket API, and the one
mental model everything else hangs off: a QUIC connection is a `struct quic_sock`
that owns many sub-objects and rides on a UDP tunnel socket, with the TLS
handshake delegated to userspace. If you read one doc before the rest, read this.

Spec: RFC 9000 (QUIC transport), RFC 9001 (QUIC-TLS), RFC 9002 (loss/CC).
Code: `net/quic/` (module `quic.ko`). Author: Xin Long (Red Hat). This is the
mainline-track in-kernel QUIC, distinct from userspace QUIC libraries.

## What this is, and what is in-kernel vs not

QUIC is normally a userspace protocol on top of UDP. This implementation moves
the QUIC **transport** (streams, flow control, loss recovery, congestion
control, packet protection, connection IDs, migration) into the kernel as a new
socket type, `IPPROTO_QUIC` (protocol number 261; `MODULE_ALIAS_NET_PF_PROTO`
at protocol.c:747-750). The application opens
`socket(AF_INET|AF_INET6, SOCK_STREAM|SOCK_DGRAM, IPPROTO_QUIC)`.

The one thing that stays in userspace is the **TLS 1.3 handshake itself**. The
kernel carries handshake bytes in CRYPTO frames and installs the resulting
traffic secrets, but it does not run TLS. A userspace handshake agent drives
the TLS exchange over the socket (sendmsg/recvmsg with a `QUIC_HANDSHAKE_INFO`
control message) and then pushes the negotiated secrets down with
`setsockopt(QUIC_SOCKOPT_CRYPTO_SECRET)`. This split is covered in
`02_handshake_crypto.md`; it is the central fact for a fuzzer, because reaching
any post-handshake code requires real secrets to have been installed.

Kconfig: `IP_QUIC` (tristate, `depends on INET && IPV6`, selects the AEAD/hash
crypto and `NET_UDP_TUNNEL`; Kconfig:6-35). A separate `IP_QUIC_TEST`
(`sample_test.c`) builds the in-tree selftest module.

## It rides on a UDP tunnel socket

QUIC does not open raw IP sockets. Each path opens (or reuses) a kernel UDP
socket via the udp_tunnel API: `quic_udp_conf_init()` (family.c:577) fills a
`udp_port_cfg`, and `quic_udp_sock_create()` (path.c) calls `udp_sock_create()` +
`setup_udp_tunnel_sock()`. Outbound packets are built and sent through
`quic_lower_xmit()` -> `udp_tunnel_xmit_skb` / `udp_tunnel6_xmit_skb`
(family.c:591, 152, 181); inbound UDP datagrams are decapsulated and the QUIC
packet is handed to `quic_packet_rcv()` (packet.c:596). Everything v4/v6 in
family.c is a `quic_v4_*` / `quic_v6_*` pair selected by a small inline
dispatcher — there is no ops vtable.

## The object model: one quic_sock, many sub-objects

`struct quic_sock` (socket.h:88-109) embeds `inet_sock` and then owns the whole
connection's machinery as inline sub-structs:

```
  userspace fd  socket(AF_INET6, SOCK_STREAM, IPPROTO_QUIC)
      |
  struct quic_sock  "quic_sk(sk)"      -- the connection
      |
      +-- streams   (quic_stream_table)     open streams + per-dir limits   [05]
      +-- source    (quic_conn_id_set)      our connection IDs              [06]
      +-- dest      (quic_conn_id_set)      peer's connection IDs           [06]
      +-- paths     (quic_path_group)       active + alternate path, PMTU   [07]
      +-- cong      (quic_cong)             congestion control (Reno)       [08]
      +-- space[3]  (quic_pnspace)          per-PN-space ack/loss state     [03]
      +-- crypto[4] (quic_crypto)           per-level keys (Init/Hs/App/0RTT)[02]
      +-- outq      (quic_outqueue)         send queues + loss recovery     [05]
      +-- inq       (quic_inqueue)          recv/reassembly queues          [05]
      +-- packet    (quic_packet)           in-progress packet build/parse  [03]
      +-- timers[5] (quic_timer)            loss/sack/path/pmtu/pace        [07]
```

Accessor inlines (`quic_streams(sk)`, `quic_source(sk)`, `quic_dest(sk)`,
`quic_paths(sk)`, `quic_cong(sk)`, `quic_pnspace(sk, level)`,
`quic_crypto(sk, level)`, `quic_outq(sk)`, `quic_inq(sk)`, `quic_packet(sk)`,
`quic_timer(sk, type)`) live at socket.h:146-204 and are how all the `.c` files
reach each sub-object. `quic6_sock` (socket.h:111) adds `ipv6_pinfo` for v6.

Note there are **three packet-number spaces** but **four crypto levels**: 0-RTT
(EARLY) and 1-RTT (APP) share one PN space — `quic_pnspace(sk, level)` maps via
`space[level % QUIC_CRYPTO_EARLY]` (socket.h:176-179), so Initial=1, Handshake=2,
App/0-RTT=0.

## The state machine reuses TCP's constants

`enum quic_state` (socket.h:34-39) aliases the TCP state constants:
`QUIC_SS_CLOSED = TCP_CLOSE`, `QUIC_SS_LISTENING = TCP_LISTEN`,
`QUIC_SS_ESTABLISHING = TCP_SYN_RECV`, `QUIC_SS_ESTABLISHED = TCP_ESTABLISHED`.
Transitions go through the single chokepoint `quic_set_state()` (socket.h:226),
which also drives the connection MIB counters (`10_mib.md`). Key transitions:

- `QUIC_SS_ESTABLISHING`: client in `quic_connect()` (socket.c:591); server on an
  accepted sock in `quic_accept_sock_setup()` (socket.c:1626).
- `QUIC_SS_LISTENING`: `quic_inet_listen()` (protocol.c:107).
- `QUIC_SS_ESTABLISHED`: at the end of `quic_sock_set_crypto_secret()`
  (socket.c:2395) — i.e. when userspace installs the final App secret and both
  directions are keyed. **This is the real "handshake done" edge.**
- `QUIC_SS_CLOSED`: `quic_close()` (socket.c:1706) and every error path.

## Lifecycle in one breath

1. **Open (client):** `quic_connect()` (socket.c:534) sets the dest addr, routes,
   auto-binds, generates source+dest connection IDs, installs Initial keys
   (derived in-kernel from the DCID; AES-GCM-128), seeds the token secret, goes
   ESTABLISHING, and arms the idle/path timers.
2. **Open (server):** `quic_inet_listen()` (protocol.c:45) goes LISTENING; an
   incoming Initial creates a `quic_request_sock` (socket.c:46); `quic_accept()`
   (socket.c:1636) clones a child sock, binds/routes it, installs Initial keys
   from the request's DCID, and drains the request's backlog.
3. **Handshake:** TLS runs in userspace; CRYPTO bytes move via
   `sendmsg`/`recvmsg` + `QUIC_HANDSHAKE_INFO`, secrets install via
   `QUIC_SOCKOPT_CRYPTO_SECRET` (`02_handshake_crypto.md`). Server sends
   NEW_TOKEN / HANDSHAKE_DONE at completion.
4. **Carry data:** `sendmsg` queues STREAM (or DATAGRAM) frames in the outqueue;
   the send pump packs frames into protected packets and transmits; the receiver
   decrypts, validates frames, reassembles, and delivers to `recvmsg`
   (`03_packet.md`, `04_frame.md`, `05_streams.md`).
5. **Maintain / migrate:** connection IDs rotate (NEW/RETIRE_CONNECTION_ID,
   `06_connid.md`); a path change triggers PATH_CHALLENGE/RESPONSE validation and
   migration (`07_path.md`); keys can update (`02`).
6. **Close:** graceful `quic_close()` -> app-level CONNECTION_CLOSE, or an error
   CONNECTION_CLOSE from a protocol violation; socket goes CLOSED.

## The send and receive paths at a glance

- **Send:** `quic_sendmsg()` (socket.c:1056) has three arms — handshake CRYPTO
  (when `QUIC_HANDSHAKE_INFO` cmsg present), DATAGRAM (`MSG_QUIC_DATAGRAM`), and
  the default STREAM path. Frames land in the outqueue (`quic_outq_*_tail`); the
  pump `quic_outq_transmit()` packs them into packets via the packet layer;
  `quic_crypto_encrypt()` protects them; `quic_lower_xmit()` sends the UDP
  datagram.
- **Receive:** UDP tunnel -> `quic_packet_rcv()` (packet.c:596) -> socket lookup
  -> `quic_packet_process()` (packet.c:2148) -> per-level decrypt + PN check +
  `quic_frame_process()` -> inqueue reassembly -> `recv_list` -> `quic_recvmsg()`
  (socket.c:1324).

## setsockopt surface (SOL_QUIC)

`quic_do_setsockopt()` (socket.c:2406) is the control plane a harness drives.
The dispatch (socket.c:2420-2463) covers EVENT, STREAM_RESET,
STREAM_STOP_SENDING, CONNECTION_ID, CONNECTION_CLOSE, CONNECTION_MIGRATION,
KEY_UPDATE, TRANSPORT_PARAM(+_EXT), CONFIG, ALPN, TOKEN, SESSION_TICKET, and
CRYPTO_SECRET (the handshake-secret install, which is zeroed from the kernel copy
after use). The getsockopt side (socket.c:2771) mirrors most of these; KEY_UPDATE
and CRYPTO_SECRET are write-only by design. The full map is in
`09_code_map.md`.

## Why this matters for fuzzing (framing)

The reachable surface splits cleanly by crypto level. Initial-level packet
parsing and Initial-frame validation are reachable blind: the Initial keys derive
from the client's Destination Connection ID, which is on the wire, so any party
(including a fuzzer) can derive them and the kernel will decrypt and parse an
Initial packet it is handed. Handshake- and App-level processing sit behind real
TLS secrets installed via sockopt — a stateful harness that owns both endpoints
(or drives/fakes the userspace handshake) installs those and then has the full
frame surface, streams, connection IDs, path validation, and migration open to
mutation. The `disable_1rtt_encryption` transport parameter (`02`) is the
shortcut that exposes 1-RTT frame processing in the clear. The per-netns MIB
drop counters (`10_mib.md`) are the cheap oracle for which gate a mutated packet
hit.

## Cross-references

- Handshake, keys, packet protection, the userspace-TLS split: `02_handshake_crypto.md`.
- Packet formats, PN spaces, the RX/TX packet machinery: `03_packet.md`.
- Every frame type and its validation/protocol-violation sites: `04_frame.md`.
- Streams, reassembly, flow control, loss recovery: `05_streams.md`.
- Connection IDs and stateless reset: `06_connid.md`. Path/migration: `07_path.md`.
- Congestion control: `08_congestion.md`. Where everything lives: `09_code_map.md`.
- The SNMP counters: `10_mib.md`.
