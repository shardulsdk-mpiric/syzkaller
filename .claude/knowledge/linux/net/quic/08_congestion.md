# Congestion control

QUIC's congestion control and RTT estimation. Short doc, because the honest
headline — like MPTCP's — is a scope statement a reviewer will ask about: this
implementation ships exactly one algorithm (NewReno) and it is **not pluggable**.

Spec: RFC 9002 (loss detection and congestion control). Code: `net/quic/cong.c`,
`net/quic/cong.h`. The ack/loss events that drive it come from the outqueue
(`05_streams.md`).

## The headline: NewReno only, not pluggable

`enum quic_cong_algo` (uapi quic.h:129-132) has a single real entry,
`QUIC_CONG_ALG_RENO`, before `QUIC_CONG_ALG_MAX`. The algorithm table
`quic_congs[]` (cong.c:96) is a one-element array holding the Reno ops. A grep of
cong.c for `struct_ops` / `bpf` returns nothing: **congestion control is hardcoded
to NewReno; there is no BPF struct_ops or other pluggable-CC hook.** This is a
deliberate contrast with MPTCP, which exposes a BPF-pluggable *scheduler* — QUIC's
cong.c has no equivalent extension point. `quic_config.congestion_control_algo`
(uapi quic.h:111) exists but can only select RENO.

## How it is wired

`struct quic_cong` (cong.h:46-81) holds the RTT estimates, the window/ssthresh,
pacing state, the current `state` (the RFC 9002 §7.3 state machine), and an
`ops` pointer plus 8 words of algorithm-private storage. `struct quic_cong_ops`
(cong.h:84-97) is the callback set: `on_packet_acked`, `on_packet_lost`,
`on_process_ecn`, `on_init` (mandatory) plus optional `on_packet_sent`,
`on_ack_recv`, `on_rtt_update`. `quic_cong_set_algo()` (cong.c:309) validates the
algorithm index and binds `ops`; `quic_cong_init()` (cong.c:333) is called at
socket init and hardwires RENO with an initial RTT of `QUIC_RTT_INIT` (333 ms,
cong.h:16).

## The NewReno state machine (RFC 9002 §7.3)

`enum quic_cong_state` (cong.h:40-44): `SLOW_START`, `RECOVERY_PERIOD`,
`CONGESTION_AVOIDANCE` (the diagram is at cong.h:20-39). The Reno ops:

- `quic_reno_on_packet_acked` (cong.c:50): in SLOW_START, additive window growth
  by the acked byte count, capped at `max_window`, moving to
  CONGESTION_AVOIDANCE once `window >= ssthresh`. In RECOVERY_PERIOD, stays until
  `time > recovery_time` then falls through to avoidance growth. In
  CONGESTION_AVOIDANCE, classic AIMD `window += mss*bytes/window`.
- `quic_reno_on_packet_lost` (cong.c:44) -> `quic_reno_handle_packet_lost`
  (cong.c:19): from SLOW_START or CONGESTION_AVOIDANCE, enters RECOVERY_PERIOD with
  `ssthresh = max(window/2, min_window)` and `window = ssthresh`; no-op if already
  recovering.
- `quic_reno_on_process_ecn` (cong.c:87): an ECN-CE increase is treated exactly
  like a loss (calls the same handler).
- `quic_reno_on_init` (cong.c:92): empty (Reno needs no private state).

The common wrappers (cong.c:125-167) add **persistent congestion** (RFC 9002 §7.6)
on top: `quic_cong_check_persistent_congestion` (cong.c:105) computes the
threshold `(srtt + max(4*rttvar, kGranularity) + max_ack_delay) *
kPersistentCongestionThreshold` and, on persistent congestion, resets straight to
SLOW_START with `window = min_window`, bypassing the normal Reno loss handler.

## RTT estimation and PTO

`quic_cong_rtt_update()` (cong.c:254) implements RFC 9002 §5: it rejects samples
with an implausible `ack_delay` or clock skew, tracks `latest_rtt` and `min_rtt`,
and on the first sample sets `smoothed_rtt = latest_rtt`, `rttvar = srtt/2`;
thereafter `srtt = (7*srtt + adjusted_rtt)/8` and
`rttvar = (3*rttvar + sample)/4` (with `ack_delay` subtracted when the sample
allows). It then calls `quic_cong_pto_update()` (cong.c:170):
`pto = srtt + max(4*rttvar, kGranularity)` (the base PTO; the App-space
`max_ack_delay` term is added in the outqueue's PTO computation, `05_streams.md`)
and `loss_delay = max(kTimeThreshold(max(srtt,latest_rtt)), kGranularity)`
(RFC 9002 §6.1.2). `quic_cong_set_srtt()` (cong.c:321) seeds the estimate from a
configured initial RTT.

RTT/PTO constants (cong.h:11-18): `QUIC_KPACKET_THRESHOLD 3`,
`QUIC_KTIME_THRESHOLD(rtt) = rtt*9/8`, `QUIC_KGRANULARITY 1000us`,
`QUIC_RTT_INIT 333ms`, `QUIC_RTT_MAX 6s`, persistent-congestion threshold 3.

## Pacing

`quic_cong_update_pacing_time()` (cong.c:198) advances `pacing_time` by the
transmit time of the sent bytes at the current `pacing_rate` (with an OS-jitter
discount), called from `on_packet_sent`. `quic_cong_pace_update()` (cong.c:218)
recomputes `pacing_rate = min(2*window*USEC_PER_SEC/srtt, max_rate)` from
`on_ack_recv`. The PACE timer (an hrtimer, `07_path.md`) flushes the send queue
when the pacing delay elapses.

## Why this matters (and for the talk)

If asked "which congestion controller, is it pluggable," the accurate answer is:
mainline in-kernel QUIC runs NewReno only, with RFC 9002 persistent-congestion and
pacing, and there is no pluggable/BPF CC hook (unlike MPTCP's BPF scheduler). A
fuzzer does not need to model multiple algorithms; the reachable CC surface is the
ack/loss/ECN event processing driven by crafted ACK frames (ranges, ECN counts)
and the RTT sampling they feed. Stating the single-algorithm scope plainly is
stronger than implying a richer CC surface that is not there.

## Cross-references

- The ack/loss/ECN events that drive these callbacks: `05_streams.md`
  (outqueue loss recovery) and `03_packet.md` (pnspace ECN validation).
- The PACE/LOSS timers: `07_path.md`.
- RTT/PTO feeding retransmission timing: `05_streams.md`.
