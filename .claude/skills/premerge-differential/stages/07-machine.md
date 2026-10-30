# Stage 7: Machine

1. Probe (read-only): `ssh <host> 'bash -s' < scripts/hwprobe.sh` — threads,
   RAM/swap, `/dev/kvm` + kvm group, disk free, toolchain, desktop load,
   services that can reboot the box (unattended-upgrades).
2. Budget: total VMs (base + patched) <= host threads - 2. 7 KASAN VMs on 8
   threads gave "no output from test machine" on BOTH sides within 10 min
   (guest boot 230 s, every qemu at 100%); 6 ran clean. A "no output" on base
   and patched alike is the host, not a series. KASAN roughly doubles guest RAM needs. ~1 vCPU + 1.5-2 GB per VM,
   leave ~1-2 GB and 1 thread for the host + manager. Overcommit leads to swap
   death, which looks like boot errors, not OOM.
3. Free the box for long runs (user runs anything needing sudo):
   disable unattended-upgrades, packagekit, snapd, cups, bluetooth, ModemManager,
   other daemons; `systemctl set-default multi-user.target`; close browsers;
   prune container images. Confirm deletions with the user first.
4. Deploy (binaries only; no private finding material leaves the build box
   unless intended): syzkaller `bin/` (built at the recorded commit), kernels
   (bzImage, vmlinux, vmlinux.o), the VM image + its ssh key, cfgs with paths
   rewritten for the host. Use `rsync --sparse` for the image. Also the kernel
   **sources** (`git ls-files` copy, ~1.8 GB per tree): set `kernel_src` to it
   and `kernel_build_src` to the build box path. Without them every repro
   fails at symbolization (`scripts/get_maintainer.pl` not found) while
   fuzzing looks healthy.
5. Host tool versions do not matter for prebuilt Go binaries; qemu must
   support `-enable-kvm -cpu host`.

Record: machine name, its measured capacity, deployed artifact hashes.
