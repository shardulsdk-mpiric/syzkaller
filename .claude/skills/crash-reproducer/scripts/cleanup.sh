#!/usr/bin/env bash
# Safely stop all reproduction-run processes and VMs.
# Usage: cleanup.sh
# Kills syz-crush, syz-repro, and qemu by EXACT (truncated) process name and PID.
# Never uses `pkill -f <pattern>` (that self-matches this shell -> exit 144) and
# never `pgrep -x qemu-system-x86_64` (comm is truncated to 'qemu-system-x86').
set -u
kill_name(){ # $1 = exact comm; TERM then KILL by PID
  local n="$1" p
  for p in $(pgrep -x "$n"); do kill "$p" 2>/dev/null && echo "  TERM $n $p"; done
  sleep 2
  for p in $(pgrep -x "$n"); do kill -9 "$p" 2>/dev/null && echo "  KILL $n $p"; done
}
echo "== stopping reproduction runs =="
kill_name syz-crush
kill_name syz-repro
sleep 1
echo "== stopping qemu VMs (comm='qemu-system-x86') =="
kill_name qemu-system-x86
sleep 1
echo "== verify =="
echo "syz-crush:$(pgrep -x syz-crush|wc -l) syz-repro:$(pgrep -x syz-repro|wc -l) qemu:$(pgrep -x qemu-system-x86|wc -l)"
