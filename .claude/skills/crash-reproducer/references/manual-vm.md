# Booting one VM by hand (for `syz-execprog -debug` diagnosis)

When syz-crush/syz-repro only tell you "no output" and you need to see *which
call* wedges or *whether* the crash fires, boot a single VM yourself and run
`syz-execprog -debug` inside it. The traps are entropy and net syntax.

## The qemu invocation that works

Copy syzkaller's own args. The two that matter (and that a naive manual boot
omits, causing a VM that looks booted but won't accept ssh):

- **`-device virtio-rng-pci`** — without an RNG device the guest crng never
  seeds, and sshd / crypto / anything needing randomness stalls indefinitely.
- **Modern net syntax** `-device <nic>,netdev=net0 -netdev user,id=net0,hostfwd=tcp:127.0.0.1:<PORT>-:22`
  (not the legacy `-net nic -net user`).

```bash
# Use the same kernel/image/ssh key your manager config points at:
KERNEL=$KERNEL_OBJ/arch/x86/boot/bzImage        # from cfg "vm.kernel"
IMAGE=$IMAGE                                     # from cfg "image"
qemu-system-x86_64 -m 2048 -smp 2 \
  -device virtio-rng-pci -enable-kvm -snapshot -cpu host \
  -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp:127.0.0.1:10922-:22 \
  -hda "$IMAGE" -kernel "$KERNEL" \
  -append "root=/dev/sda console=ttyS0 earlyprintk=serial net.ifnames=0 nokaslr" \
  -display none -serial file:serial.log -no-reboot &
```

To recover the *exact* working invocation for a given config, launch a 1-VM
syz-crush and read it off a live process:
`ps -o args= -C qemu-system-x86 | head -1`  (note the 15-char-truncated name).

## ssh + run the debugger inside

```bash
KEY=$SSHKEY; chmod 600 "$KEY"                    # from cfg "sshkey"
SSH="ssh -i $KEY -p 10922 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
# wait for it (crng seed can take ~30-60s even with virtio-rng)
until $SSH root@127.0.0.1 true 2>/dev/null; do sleep 5; done
scp -i "$KEY" -P 10922 -o StrictHostKeyChecking=no \
    bin/linux_amd64/syz-executor bin/linux_amd64/syz-execprog prog.syz root@127.0.0.1:/root/
# one run, per-call trace -> shows exactly which syscall blocks / returns
$SSH root@127.0.0.1 './syz-execprog -executor=./syz-executor -debug -threaded -procs=1 -repeat=1 prog.syz'
# loop to chase a flaky race, watching dmesg for the crash
$SSH root@127.0.0.1 './syz-execprog -executor=./syz-executor -threaded -procs=4 -repeat=0 prog.syz & dmesg -w | grep -m1 -E "WARNING|BUG"'
```

`syz-execprog` is the `linux_amd64` build (runs *inside* the VM), not a host
binary. Its rev must match the executor's, same as syz-crush.
