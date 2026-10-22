# QUIC (in-kernel) knowledge base: index and concept map

Start here. This file is the map: the reading order, what each doc covers, and a
concept index so any term has a known home. The subject is the **in-kernel QUIC**
implementation (Xin Long / Red Hat), `net/quic/`, module `quic.ko` — the
mainline-track kernel QUIC transport, not a userspace QUIC library. This KB is a
source-cited reference for that code; it documents behaviour, it does not record
findings, exploits, or reproducers.

Source read for this KB: the v15 `net/quic` tree (every `file:line` reference is
against that tree and will drift — re-grep the function names if they do not match).
Public kernel source; GPL. Spec backbone: RFC 9000 (transport), RFC 9001
(QUIC-TLS), RFC 9002 (loss/CC), RFC 9221 (datagrams), RFC 9368/9369 (version
negotiation / v2).

## Reading order

| Doc | Title | One line |
|-----|-------|----------|
| 01_overview.md | Overview and the socket model | What in-kernel QUIC is; quic_sock + its sub-objects; UDP-tunnel; userspace-TLS split |
| 02_handshake_crypto.md | Handshake and crypto | CRYPTO frames, HKDF key derivation, AEAD + header protection, disable_1rtt fake-key path, key update, tokens/Retry |
| 03_packet.md | Packets | Short/long headers, packet types per version, PN spaces, PN decode, RX/TX machinery, the drop counters |
| 04_frame.md | Frames | Every frame type + the dispatch table + every validation / protocol-violation site (file:line + errcode); the silent-drop rule; transport params |
| 05_streams.md | Streams and queues | Stream table + state machines, in/outqueue reassembly, flow control, RFC 9002 loss recovery |
| 06_connid.md | Connection IDs | Source/dest CID sets, NEW/RETIRE, source-CID hash lookup, stateless reset |
| 07_path.md | Paths | PATH_CHALLENGE/RESPONSE entropy, migration state machine, anti-amplification, PLPMTUD, timers |
| 08_congestion.md | Congestion control | NewReno only (not pluggable); RTT/PTO; pacing |
| 09_code_map.md | Concept-to-code map | Where each concept lives in net/quic/ + struct home headers |
| 10_mib.md | SNMP/MIB counters | /proc/net/quic/snmp, the QUIC_MIB_* enum, every increment site (the fuzzing oracle) |

Suggested path for a fuzzing/harness reader: 01 -> 03 -> 04 -> 02 -> 05 -> 06/07,
with 10 kept open as the drop-counter reference.

## Concept index (the "where is X" map)

| Term / concept | Lives in |
|----------------|----------|
| quic_sock and its sub-objects | 01 "The object model" |
| IPPROTO_QUIC / socket type | 01; 09 "Build / config" |
| rides on a UDP tunnel socket | 01 "It rides on a UDP tunnel socket" |
| state machine (QUIC_SS_*) | 01 "The state machine reuses TCP's constants" |
| userspace TLS handshake / crypto_level | 01, 02 "Where the handshake actually happens" |
| CRYPTO frames | 02 "CRYPTO frames"; 04 (0x06) |
| HKDF / key derivation / labels | 02 "HKDF and the label set" |
| initial keys from DCID | 02 "Initial keys" |
| cipher suites | 02 "The cipher suites" |
| AEAD payload + header protection | 02 "Per-packet protection" |
| disable_1rtt_encryption (fake keys) | 02 "The disable_1rtt_encryption fake-key path"; 04 (transport params) |
| key update | 02 "Key update" |
| tokens / Retry integrity tag / address validation | 02 "Address validation" |
| short vs long header | 03 "Two header forms" |
| packet types per version (v1/v2) | 03 "Long-header types ... crypto levels" |
| version negotiation / Retry / stateless reset (RX) | 03 "Version negotiation and Retry", "Stateless reset" |
| packet number encode/decode | 03 "Packet-number encode/decode" |
| packet-number spaces (3 spaces, 4 levels) | 03 "Packet-number spaces"; 01 |
| ECN accounting/validation | 03 "Packet-number spaces"; 08 |
| frame types / dispatch table | 04 "Frame types", "The dispatch table" |
| error -> CONNECTION_CLOSE / silent-drop rule | 04 "How an error becomes a CONNECTION_CLOSE" |
| per-frame validation sites (file:line + errcode) | 04 "Per-frame validation sites" |
| transport error codes | 04 "The transport error codes" |
| transport parameters | 04 "Transport parameters" |
| streams / stream IDs / state machines | 05 "Streams" |
| reassembly (in-order / OOO) | 05 "Receive path" |
| flow control (recv / send) | 05 "Receive path" / "Send path" |
| loss recovery / retransmission (RFC 9002) | 05 "Send path" (loss recovery) |
| connection IDs / source vs dest sets | 06 "The two sets" |
| NEW / RETIRE_CONNECTION_ID | 06 "NEW_CONNECTION_ID and RETIRE_CONNECTION_ID"; 04 (0x18/0x19) |
| source-CID hash lookup (RX demux) | 06 "Source-CID hash" |
| stateless reset token | 06 "Stateless reset" |
| path validation / PATH_CHALLENGE entropy | 07 "Path validation" |
| connection migration state machine | 07 "Migration state machine" |
| anti-amplification (3x) limit | 07 "Anti-amplification limit" |
| PLPMTUD | 07 "PLPMTUD" |
| timers (loss/sack=idle/path/pmtu/pace) | 07 "Timers" |
| congestion control (NewReno, not pluggable) | 08 |
| RTT / PTO estimation / pacing | 08 |
| /proc/net/quic/snmp and QUIC_MIB_* | 10 |
| which drop counter fires where | 10 "The counters, with exact increment sites" |

## Notes carried from the source read (verify-before-relying flags)

The extraction flagged a few things as worth re-checking at the use site before a
claim is leaned on:

- **Silent-drop vs FRAME_ENCODING (systemic).** Most raw varint/short-buffer parse
  failures inside per-frame `_process()` functions return a "bare -EINVAL" that
  leaves `frame->errcode == 0`, so the packet is silently dropped
  (`QUIC_MIB_PKT_INVFRMDROP`) rather than closing the connection. Only post-parse
  semantic checks emit a CONNECTION_CLOSE. See 04 "How an error becomes a
  CONNECTION_CLOSE." (Documented as behaviour; not assessed as a defect here.)
- **DATAGRAM errcode asymmetry.** `quic_frame_datagram_process` does not propagate
  the inqueue errcode back to `frame->errcode` the way CRYPTO/STREAM do (04). Likely
  benign (dgram-recv failures are resource-class) but not fully traced.
- **`validated` flag trigger.** The path `validated` bit (gates anti-amp) is set in
  protocol.c/packet.c, not in the PATH_RESPONSE handler; the entropy match drives
  the path *swap*. Confirm the exact trigger at those sites if it matters (07).
- **`key_update_time` source.** Not located in crypto.c; likely a sockopt/default
  in the socket layer (02).
- **Two 1200 constants.** `QUIC_PATH_MIN_PMTU` (path.h) and `QUIC_BASE_PLPMTU`
  (path.c, PLPMTUD-local) are distinct macros of the same value — do not merge (07).
- **CID limit constants.** `QUIC_CONN_ID_LIMIT/DEF/LEAST` are defined in connid.h
  but consumed outside connid.c (likely socket.c param negotiation) (06).

## Scope discipline

This KB is a clean, source-cited reference for public kernel code. It contains no
finding, exploit, reproducer, or embargo content. Fuzzing-relevance notes describe
which code is reachable and what the cheap oracles are; they are reasoning about
the public source, nothing more. Keep it that way.
