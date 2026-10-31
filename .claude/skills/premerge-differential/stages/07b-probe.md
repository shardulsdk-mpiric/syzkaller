# Stage 7b: Probe (one VM, corpus replay, before the canary)

After deploy (stage 7) and before the canary (stage 8): boot ONE VM with the
campaign's kernel + image on the fuzzing host and replay a sample of the
campaign corpus through `syz-execprog -debug`. The canary tells you programs
execute; the probe tells you whether the *calls inside them* do, which errno
they fail with, what the harness printed, and whether the protocol counters
moved. A campaign where every pseudo-syscall returns `ENOPROTOOPT` executes
programs and climbs coverage all night.

```
scripts/health_probe.sh --syz-bin <run-record>/syzkaller_<sha> \
  --kernel <bzImage> --image <image> --sshkey <key> --corpus <corpus.db> \
  --out <run-dir>/probe --n 200 --cpu 2 --mem 2048 \
  --sandbox none --procs 1 --counter-regex 'MPTcp|Tcp' \
  --must-succeed 'syz_mptcp_pair|syz_mptcp_'   # the op-set's entry points
```

Reads: `<out>/report.md` (verdict first), `per_call.csv`. Exit 2 = VM never
answered, 3 = a must-succeed call never succeeded, 4 = SYZFAIL. The VM is
killed on every exit; the image is opened with `-snapshot`.

What it does: `syz-db unpack`, every k-th program of the sorted corpus
(deterministic); qemu with syzkaller's own amd64 args (`-enable-kvm -cpu host`,
e1000 user net with a free hostfwd port, virtio-rng, `-no-reboot`) + `-snapshot`;
in the VM: `dmesg` and `/proc/net/{netstat,snmp}` before and after
`syz-execprog -executor=./syz-executor -debug -vv 1 -output -repeat=1
-sandbox/-procs/-threaded/-slowdown <as given>` under `timeout`.

Why `-debug`: it is the only way the harness diagnostics reach you (every
`common_linux_*.h` diagnostic goes through the executor's `debug()`, which
prints nothing otherwise), and it puts the call *name* on the same line as its
result (`#T [ms] <- syz_x=0xRES errno=N`), so per-call attribution does not
depend on matching program dumps to result order across procs. `-vv 1` adds
execprog's own `CALL i: ... errno N [blocked|unfinished]` lines (a
name-independent cross-check) and the machine check's disabled/transitively
disabled lists. Cost: `-debug` raises sub-second call timeouts to 1 s.

Gate (all must hold before the canary):
- exit 0; every op-set entry point in `--must-succeed` succeeded at least once;
- the counters the campaign is about moved (for MPTCP: `MPTcpExt*` non-zero,
  not just `Tcp*`) in the report's **Executor netns** table, see stage 5's
  mutation-MIB smoke check. The executor's procs run in their own netns and the
  MIB counters are per netns, so the **Init netns** table shows the ssh session
  and setup, never the programs; the probe samples every executor netns through
  `/proc/<pid>/net` every 2 s while the run lasts (a netns living < 2 s is missed);
- no flagged dmesg line that is not understood;
- the "never succeeded" list contains only calls whose failure you can explain
  from the sample (a resource the sample's programs never create, a feature the
  kernel lacks) and that explanation is written in the manifest.

Reading the per-call table: a call that never *started* was dropped by the
machine check (see that section: a missing resource-creating call, or a
feature the kernel does not have); a call that always fails with the same
errno is a harness/kernel contract problem, not fuzzing; `errno unknown` means
the executor's debug line was split by another proc's output (use `--procs 1`).

Keep `probe/` in the run record; put the probe's verdict in the manifest's
canary line.
