#!/bin/bash
# Read-only capability probe for a fuzzing host. Run as: ssh HOST 'bash -s' < hwprobe.sh
s() { echo; echo "=== $1"; }
s OS;      uname -a; cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|VERSION_ID)='; uptime
s CPU;     lscpu | grep -E 'Model name|^CPU\(s\)|Thread|Core|Socket|NUMA node|MHz|L2|L3|Virtualization|Flags' | sed 's/^Flags:.*/Flags: (see virt\/avx below)/'
           grep -o -w -E 'vmx|svm|avx2|avx512f' /proc/cpuinfo | sort | uniq -c
s MEMORY;  free -h; swapon --show; grep -E 'HugePages_Total|Hugepagesize' /proc/meminfo
s KVM;     ls -l /dev/kvm 2>&1; lsmod | grep -E '^kvm' ; id; getent group kvm
           cat /sys/module/kvm_intel/parameters/nested /sys/module/kvm_amd/parameters/nested 2>/dev/null
s DISKS;   lsblk -d -o NAME,SIZE,ROTA,MODEL,TRAN; df -hT -x tmpfs -x devtmpfs -x squashfs -x overlay
s THERMAL; command -v sensors >/dev/null && sensors 2>/dev/null | grep -E 'Tctl|Package|Core 0|temp1' | head
           cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null
s TOOLS;   for t in qemu-system-x86_64 gcc clang go make git rsync flex bison bc debootstrap b4 tmux; do
             printf '%-20s %s\n' "$t" "$(command -v $t >/dev/null && ($t --version 2>&1 | head -1) || echo MISSING)"; done
s POWER;   ls /sys/class/power_supply/ 2>/dev/null; cat /sys/class/power_supply/*/status 2>/dev/null
s LOAD;    ps -eo pcpu,pmem,comm --sort=-pcpu | head -8
s NET;     ip -br addr | grep -v '^lo'
