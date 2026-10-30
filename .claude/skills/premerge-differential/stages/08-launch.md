# Stage 8: Launch

1. **Preflight** (all must hold): keystone in both kernels; every intended
   series in the patched kernel (`git log` vs record); revs match (tool ==
   executor); cfg paths exist on this host; `net.ifnames=0`; disk free for
   workdirs; nothing else heavy running on the box.
2. **Canary** (15-20 min, same cfgs, short `-time`): pass only if the log shows
   executed programs > 0 and climbing, coverage > 0, qemu processes at high
   CPU, 0 boot-error loop. A canary that never executes programs is diagnosed
   on a single manual VM boot (see crash-reproducer `references/manual-vm.md`),
   not by retrying. `syz-diffrepro -debug` cannot be used for that (debug
   clamps the VM count to 1, below `fuzzing_vms`); run `bin/syz-manager -debug
   -config patched.cfg` instead: same VMs, executor and calls, console in the log.
   On a box with a slow disk, warm the VM image into page cache first
   (`cat <image> > /dev/null`): a first-ever launch of 6 VMs off a cold SATA
   disk left every guest idle and sshd silent (all VMs fine on the re-run).
   Stop runs by PID, never `pkill -f` through ssh (the pattern matches the
   remote shell).
3. **Launch detached**: `setsid nohup bin/syz-diffrepro ... > diffrepro.log 2>&1 &`.
   Do not prefix with `pkill -f <pattern>`: the pattern matches the launching
   shell and kills the start.
4. Write the ledger row (verdict "running") and the manifest before walking away.
