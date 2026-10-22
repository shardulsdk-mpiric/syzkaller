#!/usr/bin/env bash
# Health check for a running syz-crush / syz-repro reproduction search.
# Usage: health.sh <run.log> [<crashes-dir>] [<target-warn-regex>]
# Tells you whether the search is RUNNING CLEAN, HUNG, or in HARNESS FAILURE,
# and whether any saved crash is the real target vs infra noise.
set -u
LOG="${1:?run.log required}"
CRASHES="${2:-}"
WARNRE="${3:-}"

QN=$(pgrep -x qemu-system-x86 | wc -l)          # NOTE: comm truncates to 15 chars
QCPU=$(ps -o pcpu= -C qemu-system-x86 2>/dev/null | awk '{s+=$1} END{printf "%.0f",s}')
CRUSH=$(pgrep -x syz-crush | wc -l); REPRO=$(pgrep -x syz-repro | wc -l)
NOOUT=$(grep -c 'no output from test machine' "$LOG" 2>/dev/null)
SYZF=$(grep -ciE 'SYZFAIL|mismatching .*git revisions|unknown enabled syscall' "$LOG" 2>/dev/null)
IE=$(grep -oE 'instances executed: [0-9]+' "$LOG" 2>/dev/null | tail -1)
CR=$(grep -oE 'crashes: [0-9]+' "$LOG" 2>/dev/null | tail -1)

echo "qemu VMs: $QN   qemu CPU sum: ${QCPU:-0}%   syz-crush:$CRUSH syz-repro:$REPRO"
echo "log: ${IE:-(no instances line)} / ${CR:-crashes: 0}   no-output: $NOOUT   SYZFAIL/rev/syscall-errs: $SYZF"

verdict="UNCLEAR"
if [ "${SYZF:-0}" -gt 0 ]; then
  verdict="HARNESS FAILURE — rev-mismatch or bad enable_syscalls (see log); rebuild executor / fix config"
elif [ "$QN" -eq 0 ] && [ "$CRUSH" -eq 0 ] && [ "$REPRO" -eq 0 ]; then
  verdict="NOT RUNNING — no tool, no VMs (exited or never launched)"
elif [ "${NOOUT:-0}" -ge 3 ] && [ "${QCPU:-0%}" != "" ] && [ "${QCPU:-0}" -lt 50 ] 2>/dev/null; then
  verdict="HUNG — repeated 'no output' + low CPU; program wedges at 0 executions (check stray VMs, RWND_CLAMP payload, config)"
elif [ "$QN" -gt 0 ] && [ "${QCPU:-0}" -ge 50 ] 2>/dev/null; then
  if [ "${NOOUT:-0}" -gt 0 ]; then
    verdict="RUNNING (productive) — VMs up + CPU-active, but $NOOUT 'no output' restarts seen (some replays wedge, e.g. blocking payloads in the log); still accumulating replays. Fine for a long race-catch; investigate if no-output climbs fast and CPU drops."
  else
    verdict="RUNNING CLEAN — VMs up and CPU-active (executing), no wedged replays. For a non-crashing run this + no SYZFAIL is success; crush logs 'instances executed' only on a crash."
  fi
fi
echo "VERDICT: $verdict"

if [ -n "$CRASHES" ] && [ -d "$CRASHES" ]; then
  echo "--- saved crash titles ---"
  for d in "$CRASHES"/*/description; do [ -f "$d" ] && cat "$d"; done 2>/dev/null | sort | uniq -c
  if [ -n "$WARNRE" ]; then
    if grep -rqiE "$WARNRE" "$CRASHES" 2>/dev/null; then echo ">>> TARGET WARN/BUG signature FOUND <<<"; else echo "(target signature not yet seen; 'no output' is NOT the target)"; fi
  fi
fi
