# net/quic per-file coverage -- keystone kernel, full QUIC op-set

Per-file coverage of `net/quic`, in the shape the maintainer's own
coverage data uses (covered / total instrumented PCs per file). Produced
from a **bounded** run of the **full QUIC op-set** on the keystone kernel.
This is the artifact to show the maintainer alongside the patch + recipe.

**Gate:** this artifact was captured only after the falsification passed
(keystone introduced no new crashes and no instrumentation-named crash
buckets -- see the main README "Falsification gate"). The full-op-set run
below itself produced **0** BUG/WARN/KASAN lines in dmesg on the keystone
kernel (the real-harness falsification, incl. the Phase-3 wire mutation).

## Headline

| scope | net/quic covered / total | % |
|---|---|---|
| full op-set, union of all kcov streams (per-task + remote) | **2193 / 5121** | **42.8%** |
| of which the **remote/softirq stream** (keystone-attributed) | **1235 / 5121** | **24.1%** |

The second row is the point of the keystone: ~24% of net/quic's entire
instrumented surface is reached in the RX softirq and is attributed to the
fuzzer **only because of this patch**. Without it that coverage is flat
(`current` in softirq is not the connection's task, so per-task kcov drops
it). The RX/validation files carry the bulk of it: `packet.c` 346/891
(38.8%) and `frame.c` 209/735 (28.4%) come via the softirq stream alone.

## Per-file -- full op-set (union of per-task + remote streams)

```
file           covered    total     pct
common.c            82      177   46.3%
cong.c              30       53   56.6%
connid.c            61      102   59.8%
crypto.c           152      240   63.3%
family.c            84      390   21.5%
frame.c            377      735   51.3%
inqueue.c           89      234   38.0%
outqueue.c         231      473   48.8%
packet.c           395      891   44.3%
path.c              75      183   41.0%
pnspace.c           29       52   55.8%
protocol.c          40      248   16.1%
socket.c           409     1126   36.3%
stream.c           119      140   85.0%
timer.c             20       77   26.0%
```

## Per-file -- remote/softirq stream only (keystone-attributed)

```
file           covered    total     pct
common.c            59      177   33.3%
cong.c              26       53   49.1%
connid.c            42      102   41.2%
crypto.c            76      240   31.7%
family.c            62      390   15.9%
frame.c            209      735   28.4%
inqueue.c           67      234   28.6%
outqueue.c         159      473   33.6%
packet.c           346      891   38.8%
path.c              24      183   13.1%
pnspace.c           25       52   48.1%
protocol.c           8      248    3.2%
socket.c            45     1126    4.0%
stream.c            77      140   55.0%
timer.c             10       77   13.0%
```

`socket.c` and `protocol.c` are mostly syscall-side (per-task) code, so
their remote share is small, as expected; the RX files (`packet.c`,
`frame.c`, `crypto.c`, `outqueue.c`, `stream.c`) carry the softirq share.

## Run parameters (for the reproduction recipe)

- **Kernel:** `quic_fuzz_keystone` -- base `cd83d12e730d4` (net/quic at
  v7.3-rc2 + QUIC uapi) with this two-patch keystone series applied.
  Config = the `quic_fuzz_kasan` `.config`: `CONFIG_IP_QUIC=y`,
  `CONFIG_KCOV=y`, `CONFIG_KCOV_INSTRUMENT_ALL=y`,
  `CONFIG_KCOV_ENABLE_COMPARISONS=y`, `CONFIG_KASAN=y`. Booted `nokaslr`,
  3G / 4 vCPU snapshot VM, trixie image.
- **Harness:** syzkaller fork, branch `quic_surface`
  (`open/src/fuzzing/syzkaller_wt_quic`), executor git revision
  `ac7897c9654917221e8a80c0544e8bffca6fa441+`. The pseudo-syscalls are
  marked `(remote_cover)`, so the executor opens `KCOV_REMOTE_ENABLE` with
  its per-exec common handle -- which the keystone carries onto the QUIC
  connection, attributing the softirq RX to that handle (the `.extra`
  stream).
- **Program:** `quic_full.prog` (in this dir) -- the full op-set in one
  program, seeded:
  `syz_quic_conn_init(disable_1rtt=1)` -> `stream_open` (bidi + uni) ->
  `stream_io` x3 (c2s / s2c / uni) -> `cid_issue` -> `cid_retire` ->
  `key_update` -> `migrate` -> `wire_mutate` x3 (UNKNOWN_TYPE,
  RESERVED_BITS, STREAM_TO_RESET) -> `path_challenge` -> `conn_close`.
- **Run:** bounded.
  ```sh
  syz-execprog -executor=./syz-executor -cover -coverfile=/root/cov \
      -repeat=12 -procs=2 quic_full.prog
  ```
  ~2 min window. Collected 12 reqs x 2 procs of per-call + `.extra`
  coverfiles; unioned+deduped to 12644 PCs (all streams) and 3011 PCs
  (`.extra` / remote-softirq only).
- **Analysis:** `syz-cover -config cover.cfg -exports funccover <rawcover>`
  against the keystone `vmlinux` (DWARF), aggregated per file
  (`funccover_all.csv` / `funccover_extra.csv` in this dir).

## Caveats (do not overclaim)

- This is a bounded single-program run, not a fuzzing campaign; the
  percentages are the reachable post-handshake + validation surface this
  op-set touches, not an upper bound. A longer campaign will raise them.
- The wire-mutation validation paths are reached over the `disable_1rtt`
  (plaintext) TEST config so the mutation lands before AEAD; this is
  validation-path coverage, not AEAD-protected production traffic.
- `Total PCs` is syz-cover's per-function instrumented-PC count from the
  keystone vmlinux -- the same denominator the maintainer's coverage uses.
