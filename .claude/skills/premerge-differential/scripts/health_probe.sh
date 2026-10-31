#!/bin/bash
# Health probe for a syzkaller-based campaign. Before a long run, boot ONE qemu
# VM with the campaign's kernel + image (-snapshot: the image is never written),
# replay a deterministic sample of the campaign corpus through syz-execprog
# -debug, and write report.md + per_call.csv answering: does each call succeed,
# with what errno does it fail, what did the executor/harness print, what new
# kernel log lines appeared, did the protocol counters move.
#
# Usage: health_probe.sh --syz-bin DIR --kernel bzImage --image IMG --sshkey KEY
#                        --corpus corpus.db --out DIR [options]
#   --syz-bin DIR      pinned syzkaller bin/ (syz-db, linux_amd64/syz-executor,
#                      linux_amd64/syz-execprog)
#   --n N              programs to replay (default 200; every k-th of the sorted
#                      corpus, all if fewer)
#   --cpu N --mem MB   VM size (default 2 / 2048)
#   --cmdline STR      kernel cmdline (default: syzkaller's amd64 line + net.ifnames=0)
#   --sandbox S        execprog -sandbox (default none)      } use the campaign's
#   --procs N          execprog -procs (default 1, see below) } values
#   --threaded 0|1     execprog -threaded (default 1)
#   --slowdown N       execprog -slowdown (default 1)
#   --execprog-extra S extra execprog flags, e.g. "-disable=fault"
#   --counter-regex RE counters to report (default "MPTcp|Tcp")
#   --must-succeed RE  calls that must have >=1 success (exit 3 otherwise)
#   --ssh-timeout S    wait for sshd (default 300)
#   --run-timeout S    bound on the execprog run inside the VM (default 900)
#   --qemu BIN --qemu-extra "ARGS"   qemu binary / extra args
#   --sshuser U --port P             guest user (default root) / fixed hostfwd port
#   --sample-only      unpack + sample, write sample.list, no VM
# Every flag has an HP_<NAME> env default (HP_SYZ_BIN, HP_N, HP_COUNTER_RE ...).
#
# Exit: 0 healthy | 1 local prerequisite/usage error | 2 VM never answered ssh
#       3 a --must-succeed call had zero successes | 4 SYZFAIL in executor output.
# report.md is written for 0, 2, 3, 4. The VM is always killed (EXIT trap).
#
# --procs defaults to 1 because the executor's per-call debug lines are written
# in pieces (name/result, then errno) and several executor processes share one
# stderr: with procs>1 an errno can land on another line and is then reported
# as "errno unknown". Pass the campaign's procs when load matters more.
set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

SYZ_BIN=${HP_SYZ_BIN:-} KERNEL=${HP_KERNEL:-} IMAGE=${HP_IMAGE:-} SSHKEY=${HP_SSHKEY:-}
CORPUS=${HP_CORPUS:-} OUT=${HP_OUT:-}
N=${HP_N:-200} CPU=${HP_CPU:-2} MEM=${HP_MEM:-2048}
CMDLINE=${HP_CMDLINE:-"root=/dev/sda console=ttyS0 earlyprintk=serial net.ifnames=0 nokaslr"}
SANDBOX=${HP_SANDBOX:-none} PROCS=${HP_PROCS:-1} THREADED=${HP_THREADED:-1} SLOWDOWN=${HP_SLOWDOWN:-1}
EXECPROG_EXTRA=${HP_EXECPROG_EXTRA:-}
COUNTER_RE=${HP_COUNTER_RE:-"MPTcp|Tcp"} MUST_RE=${HP_MUST_RE:-}
SSH_TIMEOUT=${HP_SSH_TIMEOUT:-300} RUN_TIMEOUT=${HP_RUN_TIMEOUT:-900}
QEMU=${HP_QEMU:-qemu-system-x86_64} QEMU_EXTRA=${HP_QEMU_EXTRA:-}
SSHUSER=${HP_SSHUSER:-root} PORT=${HP_PORT:-} SAMPLE_ONLY=0

usage() { sed -n '2,/^set -u/p' "$0" | grep -v '^set -u' | sed 's/^# \{0,1\}//'; exit "${1:-1}"; }
die() { echo "health_probe: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case $1 in
    --syz-bin) SYZ_BIN=$2; shift ;;      --kernel) KERNEL=$2; shift ;;
    --image) IMAGE=$2; shift ;;          --sshkey) SSHKEY=$2; shift ;;
    --corpus) CORPUS=$2; shift ;;        --out) OUT=$2; shift ;;
    --n) N=$2; shift ;;                  --cpu) CPU=$2; shift ;;
    --mem) MEM=$2; shift ;;              --cmdline) CMDLINE=$2; shift ;;
    --sandbox) SANDBOX=$2; shift ;;      --procs) PROCS=$2; shift ;;
    --threaded) THREADED=$2; shift ;;    --slowdown) SLOWDOWN=$2; shift ;;
    --execprog-extra) EXECPROG_EXTRA=$2; shift ;;
    --counter-regex) COUNTER_RE=$2; shift ;;
    --must-succeed) MUST_RE=$2; shift ;;
    --ssh-timeout) SSH_TIMEOUT=$2; shift ;;
    --run-timeout) RUN_TIMEOUT=$2; shift ;;
    --qemu) QEMU=$2; shift ;;            --qemu-extra) QEMU_EXTRA=$2; shift ;;
    --sshuser) SSHUSER=$2; shift ;;      --port) PORT=$2; shift ;;
    --sample-only) SAMPLE_ONLY=1 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown flag: $1" >&2; usage ;;
  esac
  shift
done

# --- local prerequisites (exit 1: nothing started yet) ---------------------
for v in SYZ_BIN CORPUS OUT; do [ -n "${!v}" ] || die "--$(echo $v | tr 'A-Z_' 'a-z-') is required"; done
[ $SAMPLE_ONLY = 1 ] || for v in KERNEL IMAGE SSHKEY; do
  [ -n "${!v}" ] || die "--$(echo $v | tr 'A-Z_' 'a-z-') is required"; done
[ -x "$SYZ_BIN/syz-db" ] || die "$SYZ_BIN/syz-db missing (host build)"
[ -f "$CORPUS" ] || die "corpus $CORPUS missing"
[ "$N" -ge 1 ] 2>/dev/null || die "--n must be a positive integer"
command -v python3 >/dev/null || die "python3 missing (report writer)"
[ -f "$HERE/health_probe_report.py" ] || die "$HERE/health_probe_report.py missing"
if [ $SAMPLE_ONLY = 0 ]; then
  for f in "$SYZ_BIN/linux_amd64/syz-executor" "$SYZ_BIN/linux_amd64/syz-execprog" "$KERNEL" "$IMAGE" "$SSHKEY"; do
    [ -f "$f" ] || die "$f missing"; done
  for t in "$QEMU" ssh scp tar; do command -v "$t" >/dev/null || die "$t not in PATH"; done
  [ -r /dev/kvm ] && [ -w /dev/kvm ] || die "/dev/kvm not accessible (kvm group?)"
fi
[ -e "$OUT/raw" ] && die "$OUT/raw exists: a probe's output is evidence, use a new --out"
RAW=$OUT/raw
mkdir -p "$RAW/vm" || die "cannot create $RAW"

{
  echo "syz_bin=$SYZ_BIN"; echo "kernel=$KERNEL"; echo "image=$IMAGE"; echo "corpus=$CORPUS"
  echo "n=$N"; echo "cpu=$CPU"; echo "mem=$MEM"; echo "cmdline=$CMDLINE"
  echo "sandbox=$SANDBOX"; echo "procs=$PROCS"; echo "threaded=$THREADED"; echo "slowdown=$SLOWDOWN"
  echo "execprog_extra=$EXECPROG_EXTRA"; echo "counter_regex=$COUNTER_RE"; echo "must_succeed=$MUST_RE"
  echo "ssh_timeout=$SSH_TIMEOUT"; echo "run_timeout=$RUN_TIMEOUT"; echo "qemu=$QEMU $QEMU_EXTRA"
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # SHA256SUMS in the bin dir, or (the run record's pinned layout) one level up
  # listing bin/... paths.
  for d in "$SYZ_BIN" "$SYZ_BIN/.."; do
    [ -f "$d/SHA256SUMS" ] || continue
    ( cd "$d" && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1 ) && echo "syz_bin_sha256sums=ok" || echo "syz_bin_sha256sums=mismatch"
    break
  done | grep . || echo "syz_bin_sha256sums=absent"
} > "$RAW/params"
status() { echo "$1" >> "$RAW/status"; }
: > "$RAW/status"

# --- 1. unpack + deterministic sample ---------------------------------------
UNPACK=$RAW/corpus_unpacked
"$SYZ_BIN/syz-db" unpack "$CORPUS" "$UNPACK" > "$RAW/syz-db.log" 2>&1 || die "syz-db unpack failed, see $RAW/syz-db.log"
total=$(find "$UNPACK" -maxdepth 1 -type f | wc -l)
[ "$total" -gt 0 ] || die "corpus holds no programs"
k=$(( total / N )); [ "$k" -lt 1 ] && k=1
find "$UNPACK" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort \
  | awk -v k="$k" '(NR-1) % k == 0' | head -n "$N" > "$RAW/sample.list"
mkdir -p "$RAW/sample"
while read -r f; do cp "$UNPACK/$f" "$RAW/sample/"; done < "$RAW/sample.list"
sampled=$(wc -l < "$RAW/sample.list")
status "corpus_total=$total"; status "sampled=$sampled"; status "sample_step=$k"
echo "corpus: $total programs, sampled $sampled (every $k-th) -> $RAW/sample.list"
[ $SAMPLE_ONLY = 1 ] && exit 0

# --- 2. boot one VM ---------------------------------------------------------
if [ -z "$PORT" ]; then
  PORT=$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
fi
KEYDIR=$(mktemp -d); cp "$SSHKEY" "$KEYDIR/key"; chmod 600 "$KEYDIR/key"
QEMU_PID=
cleanup() {
  if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null
    for _ in 1 2 3 4 5; do kill -0 "$QEMU_PID" 2>/dev/null || break; sleep 1; done
    kill -9 "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null
    echo "qemu ($QEMU_PID) stopped"
  fi
  rm -rf "$KEYDIR"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Mirrors vm/qemu/qemu.go linux/amd64 (-enable-kvm -cpu host,migratable=off,
# e1000 + user netdev with hostfwd, virtio-rng, -no-reboot) plus -snapshot.
qemu_cmd=("$QEMU" -m "$MEM" -smp "$CPU" -enable-kvm -cpu host,migratable=off -snapshot
  -device virtio-rng-pci -device e1000,netdev=net0
  -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$PORT-:22"
  -hda "$IMAGE" -kernel "$KERNEL" -append "$CMDLINE"
  -display none -serial "file:$RAW/serial.log" -no-reboot)
if [ -n "$QEMU_EXTRA" ]; then read -r -a extra <<< "$QEMU_EXTRA"; qemu_cmd+=("${extra[@]}"); fi
printf '%q ' "${qemu_cmd[@]}" > "$RAW/qemu.cmd"; echo >> "$RAW/qemu.cmd"
"${qemu_cmd[@]}" > "$RAW/qemu.out" 2>&1 &
QEMU_PID=$!
echo "qemu pid $QEMU_PID, ssh port $PORT, serial -> $RAW/serial.log"

SSH=(ssh -i "$KEYDIR/key" -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR)
SCP=(scp -i "$KEYDIR/key" -P "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o IdentitiesOnly=yes -o BatchMode=yes -o LogLevel=ERROR -q)
VM=$SSHUSER@127.0.0.1

report() {  # always last: writes report.md/per_call.csv, its exit code is ours
  python3 -I "$HERE/health_probe_report.py" --raw "$RAW" --out "$OUT" \
    --counter-regex "$COUNTER_RE" ${MUST_RE:+--must-succeed "$MUST_RE"}
  exit $?
}

t0=$SECONDS
while ! "${SSH[@]}" "$VM" true 2>/dev/null; do
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then status "vm_answered=0"; status "qemu_exited_early=1"; report; fi
  if [ $((SECONDS - t0)) -ge "$SSH_TIMEOUT" ]; then status "vm_answered=0"; report; fi
  sleep 5
done
status "vm_answered=1"; status "boot_wait_s=$((SECONDS - t0))"
echo "ssh up after $((SECONDS - t0)) s"

# --- 3. copy in, run inside the VM -------------------------------------------
"${SSH[@]}" "$VM" 'rm -rf hp && mkdir -p hp' || { status "copy_in=0"; report; }
"${SCP[@]}" "$SYZ_BIN/linux_amd64/syz-executor" "$SYZ_BIN/linux_amd64/syz-execprog" "$VM:hp/" \
  && "${SCP[@]}" -r "$RAW/sample" "$VM:hp/sample" || { status "copy_in=0"; report; }
status "copy_in=1"

# Per-call visibility: -debug makes the executor print "#T [ms] -> call(" and
# "#T [ms] <- call=0xRES errno=N" per call, and is the only way the harness
# diagnostics (debug() in common_linux_*.h) reach stderr. -vv 1 adds execprog's
# own "CALL i: ... errno N [blocked|unfinished]" per result and the machine-check
# disabled-syscall list; -output dumps each program before execution.
cat > "$RAW/remote.sh" <<EOF
set -u
cd ~/hp || exit 97
uname -a > uname.txt
dmesg > dmesg.before 2>&1
cat /proc/net/netstat /proc/net/snmp > proc_net.before
command -v nstat >/dev/null 2>&1 && nstat -az > nstat.before 2>/dev/null
chmod +x syz-executor syz-execprog
cmd="./syz-execprog -executor=./syz-executor -debug -vv 1 -output -threaded=$THREADED -procs=$PROCS -sandbox=$SANDBOX -slowdown=$SLOWDOWN -repeat=1 $EXECPROG_EXTRA"
echo "\$cmd sample/*" > execprog.cmd
# The executor's procs run in their own netns (sandbox none/setuid/namespace),
# where the MPTCP MIB counters are kept per netns: the init-netns snapshots
# above see the ssh session, not the programs. Sample every executor netns's
# counters through /proc/<pid>/net while the run lasts; a netns starts at zero,
# so its last snapshot is its delta. Misses a netns that lives < 2 s and the
# last < 2 s of each.
mkdir -p execns
init_ns=\$(readlink /proc/1/ns/net)
timeout -k 15 $RUN_TIMEOUT \$cmd sample/* > execprog.log 2>&1 &
ep=\$!
while kill -0 \$ep 2>/dev/null; do
  for p in \$(pgrep -x syz-executor); do
    ns=\$(readlink /proc/\$p/ns/net 2>/dev/null) || continue
    [ "\$ns" = "\$init_ns" ] && continue
    id=\${ns//[^0-9]/}
    cat /proc/\$p/net/netstat /proc/\$p/net/snmp > execns/.\$id 2>/dev/null && [ -s execns/.\$id ] && mv execns/.\$id execns/\$id
  done
  sleep 2
done
wait \$ep
echo \$? > execprog.rc
dmesg > dmesg.after 2>&1
cat /proc/net/netstat /proc/net/snmp > proc_net.after
command -v nstat >/dev/null 2>&1 && nstat -az > nstat.after 2>/dev/null
exit 0
EOF
t1=$SECONDS
timeout $((RUN_TIMEOUT + 120)) "${SSH[@]}" "$VM" 'bash -s' < "$RAW/remote.sh" > "$RAW/remote.out" 2>&1
status "remote_rc=$?"; status "run_s=$((SECONDS - t1))"

# --- 4. collect (whatever exists, the VM may have died mid-run) ---------------
"${SSH[@]}" "$VM" 'cd hp && tar cf - $(ls -d dmesg.* proc_net.* nstat.* execprog.* uname.txt execns 2>/dev/null)' \
  2>/dev/null | tar xf - -C "$RAW/vm" 2>/dev/null
if [ -s "$RAW/vm/execprog.log" ]; then status "collected=1"; else status "collected=0"; fi
report
