#!/usr/bin/env bash
# Pre-flight gate for a syzkaller/BRF reproduction run.
# Usage: preflight.sh <config.cfg> <kernel-src-dir> [<bug-grep-regex>]
#   <config.cfg>        syz-crush/syz-repro manager config (JSON)
#   <kernel-src-dir>    kernel SOURCE tree whose code should contain the bug
#   <bug-grep-regex>    optional egrep pattern that must match in net/.../<file>.c
# Exits non-zero if any check fails. Fix flagged items before launching.
set -u
CFG="${1:?config.cfg required}"
KSRC="${2:-}"
BUGRE="${3:-}"
fail=0; note(){ echo "  $*"; }; ok(){ echo "PASS: $*"; }; bad(){ echo "FAIL: $*"; fail=1; }

echo "== 1. config JSON + paths =="
python3 - "$CFG" <<'PY' || { echo "FAIL: config unreadable/invalid JSON"; exit 1; }
import json,os,sys
c=json.load(open(sys.argv[1]))
for k in ("kernel_obj","image","sshkey","syzkaller"):
    p=c.get(k,""); print(("PASS" if os.path.exists(p) else "FAIL")+f": {k}={p}")
vmk=c.get("vm",{}).get("kernel","")
print(("PASS" if os.path.exists(vmk) else "FAIL")+f": vm.kernel(bzImage)={vmk}")
es=c.get("enable_syscalls",[])
print(f"PASS: enable_syscalls has {len(es)} entries" if es else "WARN: no enable_syscalls")
open("/tmp/.pf_syzdir","w").write(c.get("syzkaller",""))
PY
SYZ=$(cat /tmp/.pf_syzdir 2>/dev/null)
grep -q FAIL <(python3 -c "import json;c=json.load(open('$CFG'));print('\n'.join(str(c.get(k,'')) for k in ['kernel_obj','image','sshkey']))" 2>/dev/null) 2>/dev/null

echo "== 2. rev consistency (crush/repro/executor/HEAD must match) =="
if [ -d "$SYZ" ]; then
  HEAD=$(git -C "$SYZ" rev-parse HEAD 2>/dev/null)
  EXE=$(strings "$SYZ/bin/linux_amd64/syz-executor" 2>/dev/null | grep -m1 -oE '^[0-9a-f]{40}')
  note "tree HEAD   : $HEAD"
  note "executor rev: $EXE"
  [ -n "$EXE" ] && [ "$EXE" = "$HEAD" ] && ok "executor matches tree HEAD" || bad "executor rev != tree HEAD  (run: make executor)"
  for t in syz-crush syz-repro; do
    if [ -f "$SYZ/bin/$t" ]; then
      if strings "$SYZ/bin/$t" 2>/dev/null | grep -q "$EXE"; then ok "$t embeds executor rev"; else bad "$t rev != executor rev (rebuild both at same tree state)"; fi
    fi
  done
else bad "syzkaller dir from config not found: $SYZ"; fi

echo "== 3. kernel source contains the bug =="
if [ -n "$KSRC" ] && [ -n "$BUGRE" ]; then
  hits=$(grep -rnhE "$BUGRE" "$KSRC/net" "$KSRC/drivers" 2>/dev/null | head -5)
  [ -n "$hits" ] && { ok "bug pattern present"; echo "$hits" | sed 's/^/    /'; } || bad "bug pattern NOT found in $KSRC (kernel may be fixed/wrong tree)"
else note "(skipped — pass <kernel-src-dir> and <bug-grep-regex> to check)"; fi

echo "== 4. resources =="
note "disk: $(df -h "$(dirname "$CFG")" 2>/dev/null | awk 'NR==2{print $4" free"}')"
note "mem:  $(free -g | awk '/Mem:/{print $7"G avail"}')"
[ -e /dev/kvm ] && ok "/dev/kvm present" || bad "/dev/kvm missing (no KVM accel)"
VMCNT=$(python3 -c "import json;print(json.load(open('$CFG'))['vm'].get('count',1))" 2>/dev/null)
VMMEM=$(python3 -c "import json;print(json.load(open('$CFG'))['vm'].get('mem',0))" 2>/dev/null)
AVAIL=$(free -m | awk '/Mem:/{print $7}')
need=$(( ${VMCNT:-1} * ${VMMEM:-0} ))
[ "$need" -lt "$AVAIL" ] && ok "VM RAM ${need}MB fits ${AVAIL}MB avail" || bad "VM RAM ${need}MB (${VMCNT}x${VMMEM}) exceeds ${AVAIL}MB avail — reduce count/mem"

echo
[ "$fail" -eq 0 ] && echo "PRE-FLIGHT: ALL PASS — safe to launch" || echo "PRE-FLIGHT: FAILURES ABOVE — fix before launching"
exit $fail
