# Stage 6: Config

Derive `enable_syscalls` per group from what its series change (stage 3
reachability column), not from the previous run's list.

1. Start from the protocol op-set (pseudo-syscalls).
2. Add upstream generic calls only where a picked series needs them, e.g. for
   a send-path or sockopt series: `socket$inet{,6}_<proto>`, bind/listen/
   connect/accept, `sendmsg`/`sendto` (with the flags the series adds),
   `recvmsg` (incl. `MSG_ERRQUEUE`), `setsockopt/getsockopt$...`. Generic calls
   dilute the fuzzer's time across more programs: add what a series needs, not
   everything.
3. Harness modes the executor forces (e.g. a path-manager type latched once
   per process) can make whole series dormant regardless of syscalls. Check
   the executor for such latches before believing a series is reachable.
4. Required knobs (each cost a run once):
   - `"cmdline": "net.ifnames=0"` in the vm block (qemu amd64 default lacks
     it; without it the guest NIC is renamed, no IP, ssh never connects, 0
     programs execute).
   - `kernel_obj`, `image`, `sshkey`, `kernel` paths valid on the RUN machine.
   - `-time`, `-triage` (default -time/2), `-repros`; VM counts per the
     syz-diffrepro README (base ≥2; patched count − fuzzing VMs ≥ repro budget).
5. Validate: `syz-diffrepro` refuses unknown syscalls at startup; a pseudo-
   syscall must also be registered in `pkg/vminfo/linux_syscalls.go`.
6. **Read the machine check's "transitively disabled" list** (canary log)
   for every call you enabled. A call whose argument needs a resource no
   enabled call creates is dropped silently, e.g. every genl MPTCP PM command
   needs `ifindex` (add `ioctl$sock_SIOCGIFINDEX`). Unknown names fail loudly;
   this does not.

7. **KCSAN builds need `"ignores"`** (both cfgs): every KCSAN report reboots
   the VM, and the kernel's own timer/scheduler races fire constantly (seen:
   21 patched reboots in 14 min, mostly `tick_nohz_handler /
   tick_nohz_idle_got_tick`). `ignores` = not saved, no reboot, matched on the
   report's first line. Ignore only when BOTH sides are in a noise family,
   anchored at the function-name start, so `mptcp_*_timer / tick_*` still
   reports; test the regex against the canary's titles before use. KCSAN also
   needs `cpu >= 2` per VM: a race needs two CPUs. Boot with
   `kcsan.early_enable=0` in the vm cmdline: the executor turns KCSAN on in
   `setup_kcsan()`; with it on from boot, a race during the machine check
   aborts the whole run ("coverage is not supported ... status=Crashed").

Record the enabled list (or its hash + file) in the manifest.
8. **KCSAN kernels: build with clang, not GCC 11.** GCC 11.4 instruments
   `READ_ONCE()` of a `bool` as a plain `__tsan_read1` (the matching
   `WRITE_ONCE()` stays volatile), so correctly annotated bool pairs show up as
   data races. Check a suspect report by disassembling the read site
   (`objdump -d`, look for `__tsan_read1` vs `__tsan_unaligned_volatile_read1`).
