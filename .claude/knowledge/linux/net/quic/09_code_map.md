# Concept-to-code map

When you understand a concept and need "where is this in the tree," start here.
This maps the KB docs and QUIC concepts to files in `net/quic/` and to the structs'
home headers. Source tree: `net/quic/` (module `quic.ko`), uapi in
`include/uapi/linux/quic.h`.

## net/quic/ files by category

| File | What it holds |
|------|---------------|
| **Core / socket** | |
| socket.c | `struct proto` ops: init/destroy, bind/connect, sendmsg/recvmsg, accept, close, hash/unhash, the full `SOL_QUIC` set/getsockopt dispatch, request-sock (passive accept) machinery |
| socket.h | `struct quic_sock`/`quic6_sock`, the sub-object accessors, `enum quic_state`, `quic_set_state`, request sock |
| protocol.c | module init/exit, proto/protosw registration, per-netns init, `/proc/net/quic/{snmp,conns,eps}`, sysctls, `quic_inet_listen`/`connect`/`poll`, the SNMP name table |
| protocol.h | the `QUIC_MIB_*` enum, `struct quic_mib`/`quic_net`, `QUIC_INC/DEC_STATS` |
| common.c/common.h | varint/int get/put helpers, hash-table init, `quichdr`/`quichshdr` bitfields, `quic_skb_cb`, shared small types/constants |
| family.c/family.h | v4/v6 pairs: UDP-tunnel xmit, flow routing, addr/ECN/MTU extraction, preferred-address encode, `quic_common_set/getsockopt` |
| **Packet / PN** | |
| packet.c | RX dispatch (`quic_packet_process`/`_rcv`), long/short header parse, coalesced packets, version negotiation, Retry, stateless reset, decrypt/encrypt orchestration, TX packet build/bundle/xmit, all the INV*DROP/DEC*/ENC* counters |
| packet.h | `struct quic_packet`/`quic_packet_sent`, packet-type defines per version, taglen/MSS inlines |
| pnspace.c/pnspace.h | per-space received-PN bitmap, `quic_pnspace_check/mark/num_gabs`, ECN accounting/validation, base_pn advancement |
| **Frames** | |
| frame.c | every frame's create/process/ack, the `quic_frame_ops[]` table, `quic_frame_process` loop, all validation/protocol-violation sites, transport-param parse/build |
| frame.h | the `QUIC_FRAME_*` and `QUIC_TRANSPORT_PARAM_*` enums, `struct quic_frame`, frame predicates |
| **Streams / queues** | |
| stream.c/stream.h | `quic_stream_table`, open-or-find, limits, send/recv stream state |
| inqueue.c/inqueue.h | RX reassembly (handshake/stream/early/recv lists), receive flow control, events, datagram recv |
| outqueue.c/outqueue.h | TX queues, the send pump, RFC 9002 loss recovery/retransmission, send flow control, CONNECTION_CLOSE send |
| **Crypto** | |
| crypto.c/crypto.h | HKDF, initial-key install, secret install, AEAD + header protection, key update, tokens, Retry integrity tag |
| **Conn IDs / path / cong / timers** | |
| connid.c/connid.h | source/dest CID sets, source-CID hash lookup, NEW/RETIRE set ops, stateless-reset token |
| path.c/path.h | path validation, migration state machine, PLPMTUD; anti-amp fields (enforced in out/packet) |
| cong.c/cong.h | NewReno congestion control, RTT/PTO estimation, pacing (not pluggable) |
| timer.c/timer.h | the 5 timers (loss/sack=idle/path/pmtu/pace) and handlers |
| **Test** | |
| sample_test.c | in-tree `IP_QUIC_TEST` KUnit/sample module (NET_HANDSHAKE) |

## Concept (and KB doc) to primary code

| Concept | Doc | Primary files / functions |
|---------|-----|---------------------------|
| Socket model, quic_sock lifecycle | 01 | socket.c (quic_init_sock :443, quic_connect :534, quic_accept :1636), socket.h |
| UDP-tunnel transport | 01 | family.c (quic_lower_xmit :591, quic_flow_route :584), path.c (quic_path_bind :166) |
| State machine | 01 | socket.h (quic_set_state :226), transitions at socket.c:591/1626/1706, protocol.c:107, socket.c:2395 |
| Userspace TLS handshake split | 02 | socket.c (quic_sendmsg :1056, CRYPTO_SECRET :2228), crypto.c (set_secret :770) |
| Key derivation / initial keys | 02 | crypto.c (hkdf_expand :42, keys_derive :136, initial_keys_install :921) |
| Packet protection (AEAD + header) | 02 | crypto.c (payload_protect :469, header_protect :326, encrypt :577, decrypt :610) |
| disable_1rtt_encryption | 02, 04 | frame.c (parse :3317, build :3027), inqueue.c (:583), packet.c (xmit :2825, rx :2041) |
| Key update, tokens, Retry tag | 02 | crypto.c (key_update :836, generate/verify_token :1138/:1181, retry_tag :1004) |
| Header formats, RX dispatch | 03 | packet.c (quic_packet_process :2148, _rcv :596, handshake/app process :1562/:1979), common.h (quichdr :80) |
| Version negotiation, Retry, stateless reset | 03 | packet.c (version :757/:1279, retry :661/:1179, stateless reset :828/:1134) |
| Packet-number spaces | 03 | pnspace.c (check :73, mark :116, num_gabs :232), socket.h (quic_pnspace :176) |
| Frame dispatch + all validation | 04 | frame.c (quic_frame_ops :2503, quic_frame_process :2589, per-frame _process fns) |
| Error -> CONNECTION_CLOSE | 04 | frame.c (:2644), packet.c (quic_packet_process_error :1400, chokepoint :1419/:1434), socket.c (:2205) |
| Transport parameters | 04 | frame.c (parse :3172, build :2909), socket.c (:2205) |
| Streams + state machines | 05 | stream.c (quic_stream_get :219, create :83, put :264), uapi enums :167 |
| RX reassembly + recv flow control | 05 | inqueue.c (stream_recv :188, handshake_recv :470, flow_control :52) |
| TX pump + loss recovery | 05 | outqueue.c (transmit :334, transmitted_sack :769, retransmit_mark :1067, transmit_pto :1163) |
| Connection IDs, stateless reset | 06 | connid.c (add :110, lookup :23, remove :206, token_exists :51) |
| Path validation + migration | 07 | path.c (detect_alt :312, swap :258, pl_* PLPMTUD), frame.c (path_challenge/response :1520/:2087) |
| Anti-amplification | 07 | outqueue.c (:38), packet.c (:1601/:2249/:1786) |
| Congestion control | 08 | cong.c (reno ops :19-94, rtt_update :254, pto :170), cong.h |
| Timers | 07 | timer.c (handlers :34/:72/:88/:126/:140), timer.h |
| MIB counters | 10 | protocol.h (enum :21), protocol.c (snmp table :387, seq_show :409), increment sites across packet.c/frame.c/inqueue.c/outqueue.c/socket.c |

## Key structs and their home header

| Struct | Header |
|--------|--------|
| quic_sock / quic6_sock | net/quic/socket.h |
| quic_request_sock | net/quic/socket.h |
| quic_packet / quic_packet_sent | net/quic/packet.h |
| quic_frame / quic_frame_ops | net/quic/frame.h |
| quic_crypto / quic_cipher | net/quic/crypto.h |
| quic_conn_id(_set) / source/dest_conn_id | net/quic/connid.h |
| quic_path(_group) / quic_udp_sock | net/quic/path.h |
| quic_pnspace / quic_gap_ack_block | net/quic/pnspace.h |
| quic_stream(_table) / quic_stream_limits | net/quic/stream.h |
| quic_inqueue | net/quic/inqueue.h |
| quic_outqueue | net/quic/outqueue.h |
| quic_cong / quic_cong_ops | net/quic/cong.h |
| quic_timer | net/quic/timer.h |
| quic_mib / quic_net | net/quic/protocol.h |
| quichdr / quichshdr / quic_skb_cb / quic_conn_id | net/quic/common.h |
| transport_param, config, crypto_secret, events, errors (uapi) | include/uapi/linux/quic.h |

Rule of thumb: **internal** per-connection state lives in the per-subsystem
`net/quic/*.h`; the **userspace ABI** (transport params, config, crypto secret,
events, transport error codes, sockopt numbers) lives in
`include/uapi/linux/quic.h`.

## Build / config

- `Kconfig`: `IP_QUIC` (tristate, `depends on INET && IPV6`, selects the AEAD/hash
  crypto + `NET_UDP_TUNNEL`), `IP_QUIC_TEST` (`depends on IP_QUIC && NET_HANDSHAKE`).
- `Makefile`: `quic-y` = common family protocol socket stream connid path cong
  pnspace crypto timer packet frame outqueue inqueue.
- Protocol number: `IPPROTO_QUIC == 261` (`MODULE_ALIAS_NET_PF_PROTO(PF_INET/6, 261)`,
  protocol.c:747).

## Useful grep starting points

- `grep -rn 'QUIC_INC_STATS' net/quic` — every MIB increment site (the drop oracle).
- `grep -n 'frame->errcode =\|cb->errcode =' net/quic/*.c` — explicit error-code sites.
- `grep -n 'quic_frame_.*_process' net/quic/frame.c` — per-frame RX handlers.
- `grep -n 'QUIC_TRANSPORT_ERROR_' net/quic/*.c` — where each transport error is set.

## Cross-references

- Everything in this base: `00_index.md`. The SNMP counters: `10_mib.md`.
