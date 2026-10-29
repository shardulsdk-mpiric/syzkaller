# MPTCP path-manager selection: design note (draft for brf-a1 and Shardul)

Status: DRAFT, 2026-10-30. Direction agreed with Shardul. Not yet reviewed by brf-a1,
who owns the MPTCP harness code (`executor/common_linux_mptcp.h`,
`sys/linux/socket_mptcp_flow.txt`, the vminfo gate). Part of task
`differential_audit_yield`, work item (1), op-set reach.

Kernel line numbers: `linux_mptcp_patched_wt` (mptcp export + pending series,
2026-10). Harness line numbers: syzkaller fork `54cdc7c66`.

## 1. Problem

Each MPTCP connection (msk) is run by exactly one path manager (PM): the
in-kernel PM (`pm_kernel.c`, default) or the userspace PM (`pm_userspace.c`).
The kernel copies the netns setting into the msk in `mptcp_pm_data_reset()`
(`pm.c:1263`) at three moments:

- `socket()`, for the client and listener msks (`protocol.c:3256`);
- **handshake**, for the server-side msk (`mptcp_sk_clone_init`, `protocol.c:3840`);
- disconnect, which re-reads the netns setting (`protocol.c:3754`).

The two PMs exclude each other on one msk:

- userspace commands reject a kernel-PM msk ("userspace PM not selected",
  `pm_userspace.c:212`);
- in-kernel PM config commands skip userspace msks (`pm_kernel.c:1124/1170/1541`);
- accepting a joining subflow uses a different rule under each PM (`subflow.c:99`).

The harness's `pair_init` writes `pm_type=1` and never restores it
(`common_linux_mptcp.h:669`, called at `:919`). The netns belongs to the executor
process, and programs run in forked children that share it. So after the first
`pair_init`, every MPTCP connection in that process, harness or stock, runs the
userspace PM. Consequences:

1. **Reach.** `pm_kernel.c` never runs: endpoint-driven subflows, signal
   ADD_ADDR, fullmesh, subflow retry, limits. The round-1 audit's limit, fullmesh
   and retry series ran dormant because of this.
2. **Reproducibility.** A crash that depends on the leaked setting doesn't
   reproduce in a fresh netns (syz-repro, syz-crush, C reproducer). The
   minimizer may also wrongly drop `pair_init`.
3. **Corpus noise.** Coverage depends on what ran earlier in the process, so
   triage's repeated runs give unstable signal.

`pair_init`'s other setting flags leak the same way: `MPTCP_INIT_NO_TIMESTAMPS`
writes `net.ipv4.tcp_timestamps=0` (`:927`), and `MPTCP_INIT_CHECKSUM` writes
`net.mptcp.checksum_enabled=1` (`:940`). Neither is restored.

## 2. Principles (Shardul, 2026-10-30)

- **P1. Don't generate calls that are certain to fail.** The fork exists to
  reduce randomization on deterministic failures in protocol flows. An op that
  cannot succeed on the current state should be impossible to generate, not
  merely fail cleanly.
- **P2. Upstreamable by design.** Use idioms upstream syzkaller accepts.
- **P3. Both PMs, all flows, including real-world mixes.** The PM is local
  policy on each host and is never negotiated (RFC 8684 has no option for it), so
  mixed connections are normal in practice (e.g. an `mptcpd`-driven server with
  stock kernel-PM clients). The design must cover them.
- **P4. Every setting is visible in the program, and nothing outlives it.** This
  serves syz-repro, syz-crush, prog2c and manual analysis, and keeps corpus
  growth deterministic.

## 3. Design

### 3.1 Per-end PM, chosen in the program (P1, P3, P4)

Each end's msk takes its PM at its own creation moment, so a pair can be any of:

| client | server | real-world analogue |
|---|---|---|
| userspace | userspace | daemon on both ends (today's only mode) |
| kernel | kernel | stock Linux to stock Linux |
| userspace | kernel | daemon-driven client, stock server |
| kernel | userspace | stock client, `mptcpd`-driven server |

The choice is a `pair_init` `$variant`. The variant name records it in the
program text, so reproducers carry it.

### 3.2 Types prevent certain-to-fail ops (P1, P2)

Resource inheritance is the upstream idiom: `sock_in[sock]` → `sock_tcp[sock_in]`
→ `sock_mptcp[sock_tcp]` (`socket_inet_tcp.txt:13,17`). The PM is a property of
one end, not of the pair, and resources have a single parent. So type each end:

```
resource mptcp_msk[intptr]
resource mptcp_msk_userspace[mptcp_msk]
resource mptcp_msk_kernel[mptcp_msk]

syz_mptcp_pair_init$<client>_<server>(..., client ptr[out, mptcp_msk_<pm>],
                                          server ptr[out, mptcp_msk_<pm>]) mptcp_pair
syz_mptcp_join_subflow(client mptcp_msk_userspace, ...)  # SUBFLOW_CREATE runs on the client msk token
syz_mptcp_drive_traffic(pair mptcp_pair, ...)            # PM-agnostic ops keep taking the pair
```

The exact shape is open: handle encoding (slot + side), whether `mptcp_pair`
stays the return value, and how `mptcp_subflow` relates. The invariant is not
open: an op that needs a given PM on a given end takes that end's typed handle.

### 3.3 Set, create, restore under one lock (P4)

`pair_init` writes the client's settings, then creates the client socket and
listener. It switches the PM setting to the server's choice before the
handshake, because the server msk is created at clone time. Once the server end
has been accepted, it restores every setting it touched. All of this happens
under the existing setup lock, because executor threads share the netns.

Settings covered: the PM, `checksum_enabled`, `tcp_timestamps`. Write
`net.mptcp.path_manager` (`"kernel"`/`"userspace"`; `pm_type` has been deprecated
since v6.15, `ctrl.c:276`). Fall back to `pm_type` when `path_manager` is absent.

Open: `checksum_enabled` is also read from the listener at request time
(`subflow.c:153`), so a per-end checksum choice needs the same set-before-
handshake care. Default: checksum stays a pair-wide flag.

### 3.4 Disconnect keeps each end's PM (P1)

Disconnect re-reads the netns setting (`protocol.c:3754`). Without care, a
userspace end would come back as kernel-PM and its typed handle would lie. The
pool slot records each end's PM, and `syz_mptcp_disconnect` re-asserts it under
the lock around the disconnect, then restores.

### 3.5 Per-program netns reset (P2, P4)

The executor already restores netns state before every program:
`reset_net_namespace()` (`common_linux.h:4225`, the `net_reset` feature,
netfilter tables today). Extend it to MPTCP:

- record the PM setting, `checksum_enabled`, `tcp_timestamps`, and the in-kernel
  PM's endpoints and limits at process start;
- restore them before each program.

This is a safety net for 3.3, and it is what keeps step 2's endpoint
configuration from leaking. Check: whether `net_reset` is on in our manager
configs (it is a detected feature, off under setuid sandbox).

## 4. Increments

| step | content | flows opened | verify (VM, coverage of named functions) |
|---|---|---|---|
| **1** | 3.1-3.5; existing ops re-typed; wire-mutation ops accept any PM | today's flows without the leak; every mutation family (forged ADD_ADDR, MP_FAIL, MP_PRIO, RM_ADDR, FASTCLOSE) now also reaches in-kernel PM handlers; mixed-PM handshakes and joins | per-variant smoke tests in `sys/linux/test/`; settings restored after each program; no `"userspace PM not selected"` failures in generated programs |
| **2** | in-kernel PM configuration: endpoints (subflow, signal, fullmesh, backup), limits, flush, so they act on kernel-PM ends | limits, fullmesh, retry, endpoint-driven subflows (the dormant series) | coverage of `mptcp_pm_kernel_*`, `mptcp_pm_subflow_retry*`, `fill_*_subflows` paths |
| **3** | userspace PM completeness: ANNOUNCE, REMOVE, SET_FLAGS, typed on `mptcp_msk_userspace` (client or server end) | userspace signalling beyond subflow create/destroy | coverage of `mptcp_pm_nl_announce_doit` etc. |

Step-2 prerequisites to check first: whether in-kernel PM endpoints work with
the pair's loopback addressing (it needs distinct local addresses), and whether
stock netlink descriptions or a pair-aware op is the better carrier. Also needed:
differential configs that enable whatever carrier is chosen.

## 5. Compatibility and coordination

- **BRF precedent:** BRF fc8dd71b5 added `MPTCP_INIT_KERNEL_PM = 8` (a pair-wide
  flag). That collides with the fork's `MPTCP_INIT_CHECKSUM = 8` and does not
  cover mixed pairs. The `$variant` approach replaces the flag.
- **Corpus migration:** today's programs call `syz_mptcp_pair_init` (no
  variant). Keep that name as the `userspace_userspace` behaviour, or let
  syz-upgrade drop and re-seed. Decide with brf-a1.
- **Upstream PR:** if the `upstream-mptcp` series is still in review, don't grow
  it mid-review (status with syzkaller-upstream-30). Land this on the fork, then
  propose it upstream as a follow-up.

## 6. Decisions log

- 2026-10-30, Shardul: direction approved (per-end PM in the program, typed
  handles, restore, disconnect keeps the PM, per-program reset, three steps).
  The P1-P4 principles are his.
- 2026-10-30, brf-a1 review (`design_review_brf-a1.md`): direction approved.
  Adopted:
  - `mptcp_pair` stays the return value and the handle for PM-agnostic ops.
    Per-end typed handles are extra `ptr[out]` params carrying the same slot
    value.
  - Only the producer is typed: `join_subflow` takes `mptcp_msk_userspace`.
    `mptcp_subflow` is produced only there (verified, `socket_mptcp_flow.txt:91`),
    so `subflow_destroy`/`subflow_info` need no change.
  - The bare `syz_mptcp_pair_init` name stays as userspace/userspace, because
    banked reproducers use it.
  - **Must-do:** split `mptcp_pm_ensure_setup()`. The PM write comes out of the
    one-time latch and is done per creation moment. Family resolve and event
    subscription stay one-time, and the subscription happens only if an end is
    userspace.
  - New per-end PM field in `struct syz_mptcp_pair_slot` for disconnect.
  - Restore strictly after server accept.
  - `$variants` need no vminfo change.
  - Later synergy (not step 1): a narrow `syz_mptcp_set_sysctl` op on the §3.5
    save/restore infrastructure.
- 2026-10-30, Shardul: go for step-1 code.
- 2026-10-30, step-1 implementation notes (where the code differs from §3):
  - **Handles:** only `mptcp_client_userspace` exists in step 1. syzkaller's
    compiler rejects a resource that no call consumes, and only `join_subflow`
    consumes one today. The kernel-client handle comes with step 2, and the
    server handles with step 3.
  - **pair_init arguments:** pair_init takes `(…, flags, pm, client)`.
    Kernel-client variants pass `client const[0]`, so all variants share one C
    signature. Old 3-argument programs parse non-strict with
    `pm=0` (userspace/userspace), and their join stays linked to the pair
    (`TestMPTCPLegacyPairInitStillLinks`).
  - **Order in pair_init:**
    1. Take the netns lock and save the settings.
    2. Write timestamps/checksum.
    3. Write the client PM, then `socket()` the client.
    4. Write the server PM, then listener, `connect`, `accept`.
    5. Restore the settings and unlock.
  - **Join:** re-applies the pair's timestamps setting around SUBFLOW_CREATE,
    because the subflow SYN reads it during the call. Without that, a
    `NO_TIMESTAMPS` pair's joins would regain timestamps once pair_init restores
    the setting.
  - **Disconnect:** re-applies both the server end's PM and the pair's checksum
    setting (the kernel re-reads both, `protocol.c:3753-3754`).
  - **Reset hook:** `checkpoint/reset_net_namespace` also record/restore
    `path_manager`, `pm_type`, `checksum_enabled` and `tcp_timestamps`.
  - **Behaviour change:** `listener_close_race` and any stock `socket$inet_mptcp`
    now always get the netns default PM (in-kernel). That's what a fresh
    reproducer sees; before, they got whatever an earlier pair_init had left
    behind.
  - **Residual nondeterminism:** under `-threaded`, a stock MPTCP socket created
    by another thread while pair_init holds the lock still sees the temporary
    setting. The harness can't serialize stock syscalls.
- 2026-10-30, step 1 verified (MPTCP patched kernel, `open/run/pm_selection_test/`):
  - **Run-tests:** `syz-manager -mode run-tests -tests mptcp`: 86 OK, 1 skip, 2
    fail. The two failures are `mptcp_join_close_race` in threaded C modes
    ("call is Blocked"). That flake predates step 1: 3/24 runs fail on the
    pinned pre-change binaries, 1/24 on the new ones. Both new tests
    (`mptcp_pm_kernel`, `mptcp_pm_mixed`) pass in every mode.
  - **Coverage probe:** `mptcp_pm_kernel_init` runs only for in-kernel PM msks.
    Every call matched the prediction:
    - userspace/userspace pair_init and its disconnect: not covered;
    - kernel/kernel pair_init and its disconnect: covered;
    - the server-kernel pair's disconnect: covered;
    - the client-kernel pair's disconnect: not covered (server stays userspace);
    - `listener_close_race` after a userspace pair: covered, so the netns
      default was restored.
  - **Joins:** a userspace client joined a kernel-PM server successfully, and a
    legacy 3-argument program's join still establishes.
  - **Other checks:** single-call C reproducers build with `-Werror`, plain and
    threaded with `net_reset`.
  - `TestParsing` fails on `linux/loong64` only. That's pre-existing: the
    `.const` arches line has never listed loong64.
