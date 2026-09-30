# MPTCP protocol-flow fuzzing

This fork extends syzkaller with a **stateful MPTCP protocol-flow harness**: a set of
state-carrier pseudo-syscalls that drive real MPTCP flows (MP_CAPABLE pairing, MP_JOIN
subflows, path-manager operations, teardown races) so the fuzzer reaches the
protocol-state-gated code that a stateless, random-byte fuzzer is rejected from at the
first handshake gate.

## Attribution

This work builds on two projects and cites both:

- **Syzkaller** — Google (Dmitry Vyukov et al.), the coverage-guided kernel fuzzer this
  is a fork of.
- **BRF (BPF Runtime Fuzzer)** — Hsin-Wei Hung & Ardalan Amiri Sani, UC Irvine
  (arXiv:2305.08782), which established the state-carrier pseudo-syscall + out-parameter
  discipline on syzkaller's resource model that this harness generalizes to MPTCP.

This is an **extension** of that lineage, not a new platform. Preserve `LICENSE`,
`AUTHORS`, `CONTRIBUTORS`; cite Syzkaller and BRF in any external presentation.

## What this adds over upstream syzkaller

1. A **stateful MPTCP op-set** (`sys/linux/socket_mptcp_flow.txt` +
   `executor/common_linux_mptcp*.h`): pseudo-syscalls that carry live MPTCP session
   state (the msk pair, captured keys, subflow handles) across a program, so joins run
   on established pairs and teardown races are driven deterministically.
2. An **`mptcp_token` resource** (`getsockopt$inet_mptcp_info` → `MPTCP_PM_ATTR_TOKEN`)
   so the path-manager netlink commands can name a real msk (upstream types the token as
   a bare int32 that no valid value can reach).
3. A **differential pre-merge driver** (`tools/mpiric-diff`) that fuzzes a patched kernel
   aimed at a diff, reproduces crashes, and replays them on the base kernel to classify
   patched-only regressions. See `tools/mpiric-diff/README.md`.

## The op-set

All produce/consume real syzkaller resources (`mptcp_pair`, `mptcp_subflow`,
`mptcp_token`), so the minimizer and mutator respect the state graph.

| pseudo-syscall | what it does |
|---|---|
| `syz_mptcp_pair_init(server, client, flags)` → `mptcp_pair` | establish an MP_CAPABLE pair on loopback; `flags`: `RWND_CLAMP` (pin rcvbuf small), `CAPTURE_KEYS` (sniff the MP_CAPABLE keys off the wire for later HMAC math) |
| `syz_mptcp_pair_close(pair)` | tear the pair down (consuming) |
| `syz_mptcp_join_subflow(pair, addr_id, backup, mut_op)` → `mptcp_subflow` | drive a real MP_JOIN handshake for a new subflow; `mut_op` optionally corrupts the join's HMAC/nonce via the mutation layer |
| `syz_mptcp_subflow_destroy(subflow)` | remove a subflow via the PM |
| `syz_mptcp_subflow_info(subflow)` | read subflow state back |
| `syz_mptcp_inject_join_syn(pair)` | inject one raw MP_JOIN SYN carrying the pair's token (drives the incoming-join softirq path cheaply) |
| `syz_mptcp_join_close_race(pair)` | burst MP_JOIN SYNs while synchronously closing the accepted msk (the close/teardown race class; terminal — consumes the pair) |
| `syz_mptcp_close_server(pair)` | SO_LINGER-close the accepted server msk |
| `syz_mptcp_disconnect(pair)` | `connect(AF_UNSPEC)` disconnect of the accepted msk |
| `syz_mptcp_drive_traffic(pair, data, len)` | push data client→server; on an RWND_CLAMP pair it leaves data on the send head to exercise the softirq deferred-push path |

Plus the upstream MPTCP path-manager netlink commands (`sendmsg$MPTCP_PM_CMD_*`), now
usable end-to-end via the `mptcp_token` resource.

Multiple `syz_mptcp_join_subflow` calls can run on one pair (each yields a distinct
`mptcp_subflow`), so multi-subflow programs are expressible; the kernel's concurrent
subflow cap is raised via `sendmsg$MPTCP_PM_CMD_SET_LIMITS`.

## Kernel requirements

Build the target kernel with (see `dashboard/config/linux/` for base configs):

- `CONFIG_MPTCP=y`, `CONFIG_MPTCP_IPV6=y`
- `CONFIG_KASAN=y`, `CONFIG_KCOV=y`, `CONFIG_KCOV_ENABLE_COMPARISONS=y`
- `CONFIG_NF_TABLES=y`, `CONFIG_NFT_QUEUE=y`, `CONFIG_NETFILTER_NETLINK_QUEUE=y`
  **built-in** — the mutation layer installs its NFQUEUE rule via raw netlink; these must
  not be modules.
- `# CONFIG_DEBUG_KMEMLEAK is not set` — kmemleak makes syz-manager skip repro generation
  for non-leak crashes, so leave it off on a bug-finding kernel (run leak-hunting as a
  separate profile).

## Getting started

```
make                       # builds manager, executor, tools (incl. the MPTCP descriptions)
```

A minimal manager config enables the op-set plus the PM/socket dependencies:

```json
{
  "target": "linux/amd64",
  "kernel_obj": "<build dir>", "kernel_src": "<kernel src>",
  "image": "<vm image>", "sshkey": "<key>", "syzkaller": "<this repo>",
  "procs": 6, "type": "qemu", "cover": true, "reproduce": true,
  "enable_syscalls": [
    "syz_mptcp_pair_init","syz_mptcp_pair_close","syz_mptcp_join_subflow",
    "syz_mptcp_subflow_destroy","syz_mptcp_subflow_info","syz_mptcp_inject_join_syn",
    "syz_mptcp_close_server","syz_mptcp_disconnect","syz_mptcp_drive_traffic",
    "syz_mptcp_join_close_race","getsockopt$inet_mptcp_info",
    "socket$inet_mptcp","socket$nl_generic","syz_genetlink_get_family_id$mptcp",
    "ioctl$sock_SIOCGIFINDEX","sendmsg$MPTCP_PM_CMD_ADD_ADDR",
    "sendmsg$MPTCP_PM_CMD_SUBFLOW_CREATE","sendmsg$MPTCP_PM_CMD_SUBFLOW_DESTROY",
    "sendmsg$MPTCP_PM_CMD_SET_LIMITS","sendmsg$MPTCP_PM_CMD_SET_FLAGS"
  ],
  "vm": {"count": 4, "kernel": "<bzImage>", "cpu": 2, "mem": 2048,
         "cmdline": "root=/dev/sda console=ttyS0 net.ifnames=0", "qemu_args": "-enable-kvm -snapshot -cpu host"}
}
```

Notes:
- `ioctl$sock_SIOCGIFINDEX` is required, or the PM netlink commands are transitively
  disabled ("missing resource ifindex").
- After changing any `.txt`/executor/`prog` code, run a full `make` (not just
  `make executor`) before starting a campaign, or the manager/executor git-revision
  handshake fails.
- The executor headers use syzkaller's `uintN` types (not `uintN_t`); `pkg/csource`
  is the authority for whether a change still builds a C reproducer.

## Differential pre-merge fuzzing

`tools/mpiric-diff` fuzzes a **patched** kernel aimed at a `git diff`, reproduces each
crash, and replays it on the **base** kernel to report patched-only regressions with a
reproducer. Build with `make` (it must carry the same git+descriptions revision as the
executor), then:

```
bin/mpiric-diff -base cfg/base.cfg -patched cfg/patched.cfg -patch series.diff -time 4h
```

See `tools/mpiric-diff/README.md` for the full flag set and output layout.

### Manual-pass discipline for race bugs (important)

The diff engine drops a reproducer below `0.4` reliability, so a **narrow race** can
trigger on the patched kernel yet be reported as `patched-only=0`. Do **not** trust the
headline for race-class targets: read the summary's FULL STORE for a title with crashes
on patched and none on base, and the run log for a "reproducer too unreliable / failed
to extract" line — that is a real trigger the auto-verdict buried. Pair race runs with a
window-widening sanitizer (KASAN) so the trigger rate, though still sub-0.4, is high
enough to fire in budget.
