# Async-path coverage annotation

How the fuzzer sees (and steers into) protocol code that runs *off* the syscall
task -- in receive softirq, workqueue, or deferred-send context. These are the
optional kernel-side patch series under `kernel_patches/` (directory name
`*_kcov_keystone`; in prose we call this **async-path coverage annotation**).

## The problem

Much protocol code does not run in the task that called the pseudo-syscall:

- MPTCP: the MP_JOIN crypto gates (`subflow_check_req`, `subflow_thmac_valid`,
  `subflow_hmac_valid`, the option parser, the ADD_ADDR HMAC + reset paths) run
  in **receive softirq**; the deferred send runs from the ACK-driven softirq
  push path.
- SCTP: chunk dispatch runs in the **receive softirq**; timers and the ICMP
  state machine run in their own contexts.

kcov's default per-task mode records nothing for code executing in softirq/other
context -- the PCs there are attributed to no task's kcov area. So without
annotation the fuzzer neither **reports** coverage for this code (you cannot see
you reached it) nor **steers** into it (coverage guidance is blind there). This
is the prerequisite for the coverage-guided-depth lever in 05.

## What upstream already provides

kcov already solves softirq attribution with **remote / common-handle
coverage** (`Documentation/dev-tools/kcov.rst`, "Remote coverage collection"): a
code section is wrapped in `kcov_remote_start_common(handle)` /
`kcov_remote_stop()`, and the userspace collector enables `KCOV_REMOTE_ENABLE`
with a matching common handle. The executor already issues exactly that enable
(`KCOV_REMOTE_ENABLE` with `kcov_common_handle()`), so **nothing on the
userspace/ioctl side changes**. What is missing on a stock kernel is only the
in-kernel *wraps* around the protocol's async sections, and a way to feed them the
fuzzer's handle.

## Two ways to carry the handle

**(a) in-kernel capture** -- grab `current->kcov_handle` into the connection
object (msk / SCTP endpoint/assoc) at create/connect/listen time, and read it
back at the async site. Works, but adds a new `u64` to protocol state purely for
coverage and needs listener->request_sock->child threading on the passive side.
Weaker to upstream (it duplicates data the skb already carries).

**(b) skb-carried handle** -- do nothing new to carry it: `__alloc_skb` already
stamps every freshly allocated skb with the allocating task's common handle
(`skb_set_kcov_handle`), and the async consumer reads it back with
`kcov_remote_start_common(skb_get_kcov_handle(skb))`. This is the pattern
mac80211 RX / NFC NCI / Bluetooth HCI RX already carry. In the harness's loopback
environment the peer's transmit allocates the RX skb *in the fuzzer task*, so the
handle lands on exactly the SYN / SYN-ACK / 3rd-ACK (MPTCP) and the received
chunk (SCTP) that drive the gates.

**Recommendation: (b).** The handle-carrying half is 100% upstream already; the
only residual change is a small, non-UAPI set of
`kcov_remote_start_common(skb_get_kcov_handle(skb))` / `kcov_remote_stop()` wraps
in the protocol's receive path -- the same category of patch five subsystems
already carry, and realistically upstreamable. Full analysis and verified code
pointers: `.claude/designs/kcov_no_uapi_coverage.md` in the BRF tree.

## Why no new UAPI matters

No new UAPI means:

- the harness can target a **stock** `CONFIG_<proto> + CONFIG_KCOV` kernel, not a
  privately patched one -- the single biggest adoptability lever;
- there is no measurement-fairness shim to maintain for a baseline comparison;
- the residual wraps are plausibly upstreamable, after which they disappear for
  anyone on a new-enough kernel.

## Where the annotation lives

| series | covers |
|---|---|
| `kernel_patches/mptcp_kcov_keystone/` | handle capture + annotation helper; MP_JOIN / ADD_ADDR validation gates; the deferred-send softirq path; passive-side capture in `mptcp_init_sock` |
| `kernel_patches/sctp_kcov_keystone/` | capture + annotation helper; receive-softirq chunk dispatch; timer + ICMP state-machine entry points |

Each series requires a base recent enough to have the `kcov_common_handle_id`
wrapper. See `kernel_patches/README.md` for the apply/regenerate commands.

## Optional by construction

The harness runs **without** these patches -- it is just coverage-blind on the
async paths (you still reach the code, you just cannot see or steer it). They are
applied identically on both arms of a differential run so they cancel in the
attribution (see 04). A new protocol whose deep code runs off-task wants its own
small annotation series; a protocol whose target code runs in the calling task
does not need one.

QUIC note: the RX-validation coverage for the QUIC wire-mutation path is not
attributed without an analogous QUIC annotation series (a small future item); for
that surface the SNMP counters are the current oracle for "the path ran."
</content>
