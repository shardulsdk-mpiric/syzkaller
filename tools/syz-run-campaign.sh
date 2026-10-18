#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
#
# syz-run-campaign.sh: launch a syz-manager fuzzing campaign with pre-flight
# guard rails and minimal workdir management.
#
# Lineage / attribution
#   This runner ships with the protocol-flow fuzzing harness, which is an
#   EXTENSION of two upstream projects; it does not replace or claim either:
#     * syzkaller: Google, Dmitry Vyukov et al.  https://github.com/google/syzkaller
#     * BRF: the eBPF Runtime Fuzzer, Hsin-Wei Hung and Ardalan Amiri Sani
#       (UC Irvine), arXiv:2305.08782, itself a syzkaller fork.
#   The harness lifts BRF's state-carrier pseudo-syscall pattern to kernel
#   transport-protocol flows (MPTCP, QUIC, SCTP, ...).  All of the fuzzing
#   machinery this script drives is syz-manager's own.
#
# WHAT THIS SCRIPT DOES
#   1. Checks host dependencies: jq, the qemu binary for the target arch,
#      /dev/kvm access, and (optionally) ss/lsof for the port check.
#   2. Validates the syz-manager config BEFORE launch: well-formed JSON,
#      required fields present and non-empty (target, http, workdir,
#      kernel_obj, image, sshkey, syzkaller, enable_syscalls, vm.kernel),
#      every referenced path exists, syz-manager and syz-executor are built,
#      the sshkey has sane permissions, the http port is not already taken.
#   3. Creates the workdir if missing (optionally overriding the cfg's
#      "workdir" via --workdir / SYZ_WORKDIR), refuses to double-launch into
#      a workdir that already has a live manager, and reports whether the
#      corpus is being reused or started cold.
#   4. Runs syz-manager in the foreground, tee-ing its output to a timestamped
#      log under <workdir>/logs/, forwarding SIGINT/SIGTERM so VMs are torn
#      down cleanly, and prints the dashboard URL and where crashes/corpus land.
#   5. On request (--clean) wipes a campaign's workdir state so a fresh run can
#      start; --check runs all pre-flight checks and exits without launching.
#
# WHAT THIS SCRIPT DOES NOT DO (one-time setup, do these first)
#   * Build syzkaller / the harness:
#         cd <syzkaller checkout> && make            # see docs/linux/setup.md
#     This produces bin/syz-manager and bin/linux_amd64/syz-executor.
#   * Build the target kernel with KCOV + KASAN (+ whatever the harness needs,
#     e.g. CONFIG_MPTCP=y): see docs/linux/kernel_configs.md.  The cfg's
#     "kernel_obj" is the build dir (must contain vmlinux); "vm.kernel" is the
#     bzImage.
#   * Create the VM root filesystem and its ssh key:
#         tools/create-image.sh                       # yields <name>.img + <name>.id_rsa
#   * Write the syz-manager config.  Start from docs/configuration.md and the
#     example cfg that ships with the harness, and fill in the paths above.
#     Use ABSOLUTE paths: syz-manager resolves relative cfg paths against its
#     current working directory, not the cfg file's location.
#   * Run a long campaign unattended.  This script stays in the foreground
#     (upstream convention); wrap it in tmux/screen/nohup for multi-day runs.
#
# USAGE
#   syz-run-campaign.sh --config <manager.cfg> [--workdir <dir>] [options] [-- <syz-manager args>]
#
#   Options
#     -c, --config PATH      syz-manager JSON config            (env: SYZ_CONFIG)   [required]
#     -w, --workdir PATH     override the cfg "workdir"; created if missing (env: SYZ_WORKDIR)
#     -s, --syzkaller PATH   override the cfg "syzkaller" checkout dir (env: SYZKALLER_DIR)
#     -l, --log-dir PATH     where to tee the manager log (default: <workdir>/logs)
#         --check            run every pre-flight check, print the summary, do not launch
#         --clean            remove campaign state from the workdir (crashes/, instance-*/,
#                            corpus.db, logs/) and exit; asks for confirmation unless --yes
#         --keep-corpus      with --clean: keep corpus.db (the campaign's learned state)
#     -y, --yes              answer yes to the --clean confirmation
#         --debug            pass -debug to syz-manager (single VM, verbose; for diagnosing boot)
#         --no-kvm-check     skip the /dev/kvm check (only if your qemu_args drop -enable-kvm)
#     -h, --help             this text
#
#   Anything after "--" is passed to syz-manager verbatim (e.g. -- -vv 1 -bench stats.json).
#
#   Examples
#     syz-run-campaign.sh -c mptcp.cfg --check
#     syz-run-campaign.sh -c mptcp.cfg -w /data/fuzz/mptcp_run1
#     SYZ_CONFIG=quic.cfg SYZ_WORKDIR=/data/fuzz/quic syz-run-campaign.sh
#     syz-run-campaign.sh -c mptcp.cfg -w /data/fuzz/mptcp_run1 --clean --keep-corpus
#
# WHERE THE DATA LANDS (all under the workdir; syz-manager owns the layout)
#     <workdir>/crashes/<hash>/       one dir per unique crash: description, logN,
#                                     reportN, and repro.prog / repro.c once a
#                                     reproducer is found
#     <workdir>/corpus.db             the corpus; reloaded on every start, so the
#                                     campaign resumes where it left off
#     <workdir>/instance-N/           per-VM scratch (safe to delete when stopped)
#     <workdir>/logs/manager_<ts>.log this script's tee of syz-manager's output
#     <workdir>/logs/effective_<ts>.cfg the exact cfg handed to syz-manager
#     http://<cfg http>/              live dashboard: coverage, crashes, corpus, stats
#
# Exit codes: 0 ok, 1 pre-flight failure or bad usage, otherwise syz-manager's own code.

set -euo pipefail

SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
if [ -t 2 ]; then
    C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_OFF=$'\033[0m'
else
    C_RED=""; C_YEL=""; C_GRN=""; C_OFF=""
fi

info() { printf '%s\n' "$*"; }
ok()   { printf '%s  ok  %s%s\n' "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '%s warn %s%s\n' "$C_YEL" "$C_OFF" "$*" >&2; WARNINGS=$((WARNINGS + 1)); }
fail() { printf '%s FAIL %s%s\n' "$C_RED" "$C_OFF" "$*" >&2; FAILURES=$((FAILURES + 1)); }
die()  { printf '%s%s: error:%s %s\n' "$C_RED" "$SCRIPT_NAME" "$C_OFF" "$*" >&2; exit 1; }

usage() {
    # Print the USAGE block from the header (between "# USAGE" and the next blank "#").
    sed -n '/^# USAGE/,/^# WHERE THE DATA LANDS/p' "${BASH_SOURCE[0]}" \
        | sed -e '$d' -e 's/^# \{0,1\}//'
}

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------
CFG="${SYZ_CONFIG:-}"
WORKDIR_OVERRIDE="${SYZ_WORKDIR:-}"
SYZKALLER_OVERRIDE="${SYZKALLER_DIR:-}"
LOG_DIR_OVERRIDE=""
MODE="run"              # run | check | clean
ASSUME_YES=0
KEEP_CORPUS=0
MANAGER_DEBUG=0
KVM_CHECK=1
EXTRA_ARGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        -c|--config)     [ $# -ge 2 ] || die "$1 needs a value"; CFG="$2"; shift 2 ;;
        --config=*)      CFG="${1#*=}"; shift ;;
        -w|--workdir)    [ $# -ge 2 ] || die "$1 needs a value"; WORKDIR_OVERRIDE="$2"; shift 2 ;;
        --workdir=*)     WORKDIR_OVERRIDE="${1#*=}"; shift ;;
        -s|--syzkaller)  [ $# -ge 2 ] || die "$1 needs a value"; SYZKALLER_OVERRIDE="$2"; shift 2 ;;
        --syzkaller=*)   SYZKALLER_OVERRIDE="${1#*=}"; shift ;;
        -l|--log-dir)    [ $# -ge 2 ] || die "$1 needs a value"; LOG_DIR_OVERRIDE="$2"; shift 2 ;;
        --log-dir=*)     LOG_DIR_OVERRIDE="${1#*=}"; shift ;;
        --check)         MODE="check"; shift ;;
        --clean)         MODE="clean"; shift ;;
        --keep-corpus)   KEEP_CORPUS=1; shift ;;
        -y|--yes)        ASSUME_YES=1; shift ;;
        --debug)         MANAGER_DEBUG=1; shift ;;
        --no-kvm-check)  KVM_CHECK=0; shift ;;
        -h|--help)       usage; exit 0 ;;
        --)              shift; EXTRA_ARGS=("$@"); break ;;
        -*)              die "unknown option '$1' (see --help)" ;;
        *)               die "unexpected argument '$1' (pass syz-manager args after --)" ;;
    esac
done

[ -n "$CFG" ] || { usage >&2; die "--config is required (or set SYZ_CONFIG)"; }
[ -f "$CFG" ] || die "config not found: $CFG"

# --------------------------------------------------------------------------
# Dependency: jq (needed for every cfg check below, so it goes first)
# --------------------------------------------------------------------------
command -v jq >/dev/null 2>&1 \
    || die "jq is required to validate the config. Install it (Debian/Ubuntu: sudo apt install jq; Fedora: sudo dnf install jq)."

jq -e . "$CFG" >/dev/null 2>&1 \
    || die "config is not valid JSON: $CFG
  hint: $(jq . "$CFG" 2>&1 | head -n 1)
  (note: syz-manager accepts // comments in cfg files, this script does not; strip them or use JSON proper)"

# cfg_get <jq path>  -> prints the string value, or "" if null/missing.
cfg_get() { jq -r "$1 // empty" "$CFG"; }

# --------------------------------------------------------------------------
# Build the effective config (cfg + command-line overrides)
# --------------------------------------------------------------------------
WORKDIR="${WORKDIR_OVERRIDE:-$(cfg_get '.workdir')}"
SYZKALLER="${SYZKALLER_OVERRIDE:-$(cfg_get '.syzkaller')}"
[ -n "$WORKDIR" ]   || die "no workdir: set \"workdir\" in the cfg or pass --workdir / SYZ_WORKDIR"
[ -n "$SYZKALLER" ] || die "no syzkaller dir: set \"syzkaller\" in the cfg or pass --syzkaller / SYZKALLER_DIR"

# Absolutize so the effective cfg is independent of where syz-manager is started.
abspath() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s/%s\n' "$PWD" "$1" ;; esac; }
WORKDIR="$(abspath "$WORKDIR")"
SYZKALLER="$(abspath "$SYZKALLER")"
LOG_DIR="${LOG_DIR_OVERRIDE:-$WORKDIR/logs}"
LOG_DIR="$(abspath "$LOG_DIR")"
PIDFILE="$WORKDIR/.syz-run-campaign.pid"

TARGET="$(cfg_get '.target')"
HTTP="$(cfg_get '.http')"
KERNEL_OBJ="$(cfg_get '.kernel_obj')"
IMAGE="$(cfg_get '.image')"
SSHKEY="$(cfg_get '.sshkey')"
VM_KERNEL="$(cfg_get '.vm.kernel')"
VM_TYPE="$(cfg_get '.type')"
VM_QEMU="$(cfg_get '.vm.qemu')"
VM_QEMU_ARGS="$(cfg_get '.vm.qemu_args')"
VM_COUNT="$(cfg_get '.vm.count')"
ENABLED_COUNT="$(jq -r '(.enable_syscalls // []) | length' "$CFG")"

TARGET_OS="${TARGET%%/*}"
TARGET_ARCH="${TARGET##*/}"

# --------------------------------------------------------------------------
# Running-manager detection (used by run, check and clean)
# --------------------------------------------------------------------------
live_manager_pid() {
    # Prints the pid of a live manager launched by this script into $WORKDIR, or nothing.
    local pid
    [ -f "$PIDFILE" ] || return 0
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && printf '%s\n' "$pid"
    return 0
}

port_listener() {
    # Prints whatever is listening on TCP port $1 (best effort), or nothing.
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltnp 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" {print; found=1} END {exit !found}' || true
    elif command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | tail -n +2 || true
    fi
}

# --------------------------------------------------------------------------
# --clean: wipe campaign state and exit
# --------------------------------------------------------------------------
if [ "$MODE" = "clean" ]; then
    [ -d "$WORKDIR" ] || { info "workdir does not exist, nothing to clean: $WORKDIR"; exit 0; }
    pid="$(live_manager_pid)"
    [ -z "$pid" ] || die "a manager launched from this workdir is still running (pid $pid); stop it first"

    info "About to remove campaign state under: $WORKDIR"
    info "  crashes/        $(find "$WORKDIR/crashes" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l) crash dir(s)"
    info "  instance-*/     $(find "$WORKDIR" -mindepth 1 -maxdepth 1 -type d -name 'instance-*' 2>/dev/null | wc -l) dir(s)"
    info "  logs/           $(find "$LOG_DIR" -type f 2>/dev/null | wc -l) file(s)"
    if [ -f "$WORKDIR/corpus.db" ]; then
        if [ "$KEEP_CORPUS" = 1 ]; then
            info "  corpus.db       KEPT (--keep-corpus)"
        else
            info "  corpus.db       $(wc -c <"$WORKDIR/corpus.db") bytes, WILL BE DELETED (use --keep-corpus to retain)"
        fi
    fi
    if [ "$ASSUME_YES" != 1 ]; then
        [ -t 0 ] || die "refusing to clean without confirmation on a non-interactive stdin; pass --yes"
        printf 'Proceed? [y/N] '
        read -r reply
        case "$reply" in y|Y|yes|YES) ;; *) info "aborted."; exit 1 ;; esac
    fi
    rm -rf "$WORKDIR/crashes"
    find "$WORKDIR" -mindepth 1 -maxdepth 1 -type d -name 'instance-*' -exec rm -rf {} +
    rm -rf "$LOG_DIR"
    [ "$KEEP_CORPUS" = 1 ] || rm -f "$WORKDIR/corpus.db"
    rm -f "$PIDFILE"
    info "cleaned: $WORKDIR"
    exit 0
fi

# --------------------------------------------------------------------------
# Pre-flight checks
# --------------------------------------------------------------------------
WARNINGS=0
FAILURES=0

info "== $SCRIPT_NAME: pre-flight =="
info "config:    $CFG"
info "workdir:   $WORKDIR"
info "syzkaller: $SYZKALLER"
info ""

# --- required cfg fields -------------------------------------------------
req_nonempty() {        # req_nonempty <label> <value>
    if [ -n "$2" ]; then ok "cfg $1 = $2"; else fail "cfg \"$1\" is missing or empty"; fi
}
req_nonempty target     "$TARGET"
req_nonempty http       "$HTTP"
req_nonempty kernel_obj "$KERNEL_OBJ"
req_nonempty image      "$IMAGE"
req_nonempty sshkey     "$SSHKEY"
req_nonempty vm.kernel  "$VM_KERNEL"
# workdir / syzkaller were already required above (possibly from overrides).
ok "cfg workdir = $WORKDIR${WORKDIR_OVERRIDE:+  (override)}"
ok "cfg syzkaller = $SYZKALLER${SYZKALLER_OVERRIDE:+  (override)}"

if [ "$ENABLED_COUNT" -gt 0 ] 2>/dev/null; then
    ok "cfg enable_syscalls: $ENABLED_COUNT entries"
else
    fail "cfg \"enable_syscalls\" is missing or empty; a protocol-harness campaign must scope the syscall set (see the harness example cfg)"
fi

case "$TARGET" in
    */*) ;;
    "")  ;;   # already reported
    *)   fail "cfg target must look like \"linux/amd64\", got \"$TARGET\"" ;;
esac

if [ -n "$VM_TYPE" ] && [ "$VM_TYPE" != "qemu" ]; then
    warn "cfg type is \"$VM_TYPE\"; this script's qemu/KVM checks assume \"qemu\" and are skipped"
fi

# --- referenced paths ----------------------------------------------------
check_dir()  { if [ -d "$2" ]; then ok "$1 dir exists: $2"; else fail "$1 dir not found: $2${3:+  ($3)}"; fi; }
check_file() { if [ -f "$2" ]; then ok "$1 exists: $2"; else fail "$1 not found: $2${3:+  ($3)}"; fi; }

[ -z "$KERNEL_OBJ" ] || check_dir "kernel_obj" "$KERNEL_OBJ" "point it at the kernel build dir"
if [ -d "$KERNEL_OBJ" ] && [ ! -f "$KERNEL_OBJ/vmlinux" ]; then
    warn "kernel_obj has no vmlinux ($KERNEL_OBJ/vmlinux); crash symbolization and coverage reports need it"
fi
[ -z "$VM_KERNEL" ] || check_file "vm.kernel" "$VM_KERNEL" "the bzImage from the kernel build"
[ -z "$IMAGE" ]     || check_file "image" "$IMAGE" "the rootfs from tools/create-image.sh"
if [ -n "$SSHKEY" ]; then
    check_file "sshkey" "$SSHKEY" "the .id_rsa produced next to the image by tools/create-image.sh"
    if [ -f "$SSHKEY" ]; then
        perms="$(stat -c '%a' "$SSHKEY" 2>/dev/null || stat -f '%Lp' "$SSHKEY" 2>/dev/null || echo '?')"
        case "$perms" in
            600|400) ;;
            *) warn "sshkey permissions are $perms; ssh refuses group/world-readable keys (chmod 600 $SSHKEY)" ;;
        esac
    fi
fi

# --- syzkaller binaries ---------------------------------------------------
MANAGER_BIN="$SYZKALLER/bin/syz-manager"
EXECUTOR_BIN="$SYZKALLER/bin/${TARGET_OS}_${TARGET_ARCH}/syz-executor"
check_dir "syzkaller" "$SYZKALLER" "the syzkaller/harness checkout"
if [ -x "$MANAGER_BIN" ]; then
    ok "syz-manager built: $MANAGER_BIN"
else
    fail "syz-manager not built at $MANAGER_BIN  (run: cd $SYZKALLER && make)"
fi
if [ -n "$TARGET_OS" ] && [ -n "$TARGET_ARCH" ]; then
    if [ -x "$EXECUTOR_BIN" ]; then
        ok "syz-executor built: $EXECUTOR_BIN"
    else
        fail "syz-executor not built at $EXECUTOR_BIN  (run: cd $SYZKALLER && make; for a non-native target also set TARGETARCH=$TARGET_ARCH)"
    fi
fi

# Best-effort sanity: every syz_* pseudo-syscall in enable_syscalls should be
# described in this checkout.  A miss usually means the wrong branch/checkout
# (the harness pseudo-syscalls are not in upstream syzkaller).
if [ -d "$SYZKALLER/sys/$TARGET_OS" ] && [ "$ENABLED_COUNT" -gt 0 ] 2>/dev/null; then
    missing=()
    while IFS= read -r sc; do
        [ -n "$sc" ] || continue
        base="${sc%%\$*}"                  # strip $variant
        grep -rqE "^${base}(\\\$[A-Za-z0-9_]+)?\\(" "$SYZKALLER/sys/$TARGET_OS/"*.txt 2>/dev/null \
            || missing+=("$sc")
    done < <(jq -r '.enable_syscalls[] | select(startswith("syz_"))' "$CFG")
    if [ "${#missing[@]}" -eq 0 ]; then
        ok "all syz_* entries in enable_syscalls are described in $SYZKALLER/sys/$TARGET_OS/"
    else
        warn "these enable_syscalls entries are not described in $SYZKALLER/sys/$TARGET_OS/ (wrong checkout/branch?): ${missing[*]}"
    fi
fi

# --- host: qemu + KVM -----------------------------------------------------
if [ -z "$VM_TYPE" ] || [ "$VM_TYPE" = "qemu" ]; then
    if [ -n "$VM_QEMU" ]; then
        QEMU_BIN="$VM_QEMU"
    else
        case "$TARGET_ARCH" in
            amd64)    QEMU_BIN="qemu-system-x86_64" ;;
            386)      QEMU_BIN="qemu-system-i386" ;;
            arm64)    QEMU_BIN="qemu-system-aarch64" ;;
            arm)      QEMU_BIN="qemu-system-arm" ;;
            riscv64)  QEMU_BIN="qemu-system-riscv64" ;;
            s390x)    QEMU_BIN="qemu-system-s390x" ;;
            ppc64le)  QEMU_BIN="qemu-system-ppc64" ;;
            mips64le) QEMU_BIN="qemu-system-mips64el" ;;
            *)        QEMU_BIN="qemu-system-x86_64" ;;
        esac
    fi
    if command -v "$QEMU_BIN" >/dev/null 2>&1; then
        ok "$QEMU_BIN on PATH: $(command -v "$QEMU_BIN")"
    else
        fail "$QEMU_BIN not on PATH  (Debian/Ubuntu: sudo apt install qemu-system-x86; Fedora: sudo dnf install qemu-system-x86)"
    fi

    # syz-manager's qemu backend passes -enable-kvm by default on x86; a user
    # who sets vm.qemu_args without it is running TCG on purpose (slow but legal).
    if [ "$KVM_CHECK" = 1 ]; then
        if [ -n "$VM_QEMU_ARGS" ] && [[ "$VM_QEMU_ARGS" != *enable-kvm* ]] && [[ "$VM_QEMU_ARGS" != *accel=kvm* ]]; then
            warn "vm.qemu_args does not enable KVM; VMs will run under TCG (very slow). Skipping /dev/kvm check."
        elif [ ! -e /dev/kvm ]; then
            fail "/dev/kvm does not exist: KVM is not available (enable VT-x/AMD-V in firmware; inside a VM, enable nested virtualization). Use --no-kvm-check to override."
        elif [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
            fail "/dev/kvm is not readable+writable by $(id -un)  (sudo usermod -aG kvm $(id -un), then log out and back in)"
        else
            ok "/dev/kvm usable"
        fi
    else
        warn "KVM check skipped (--no-kvm-check)"
    fi
fi

# --- http dashboard port --------------------------------------------------
HTTP_HOST="${HTTP%:*}"
HTTP_PORT="${HTTP##*:}"
[ -n "$HTTP_HOST" ] && [ "$HTTP_HOST" != "$HTTP" ] || HTTP_HOST="127.0.0.1"
if [ -n "$HTTP" ]; then
    if ! [[ "$HTTP_PORT" =~ ^[0-9]+$ ]]; then
        fail "cfg http must be host:port (e.g. \"127.0.0.1:56741\"), got \"$HTTP\""
    elif ! command -v ss >/dev/null 2>&1 && ! command -v lsof >/dev/null 2>&1; then
        warn "neither ss nor lsof found; cannot check whether port $HTTP_PORT is free"
    else
        listener="$(port_listener "$HTTP_PORT")"
        if [ -n "$listener" ]; then
            warn "http port $HTTP_PORT is already in use; syz-manager will fail to bind. Pick another \"http\" port in the cfg. Listener: $listener"
        else
            ok "http port $HTTP_PORT is free"
        fi
    fi
fi

# --- workdir ------------------------------------------------------------
if [ -d "$WORKDIR" ]; then
    ok "workdir exists: $WORKDIR"
else
    if mkdir -p "$WORKDIR" 2>/dev/null; then
        ok "workdir created: $WORKDIR"
    else
        fail "cannot create workdir: $WORKDIR"
    fi
fi
if [ -d "$WORKDIR" ] && [ ! -w "$WORKDIR" ]; then
    fail "workdir is not writable: $WORKDIR"
fi
pid="$(live_manager_pid)"
if [ -n "$pid" ]; then
    fail "a manager launched from this workdir is already running (pid $pid). Stop it, or use a different --workdir."
fi
if [ -f "$WORKDIR/corpus.db" ]; then
    ok "corpus: reusing $WORKDIR/corpus.db ($(wc -c <"$WORKDIR/corpus.db") bytes); the campaign resumes"
else
    ok "corpus: none yet; cold start (syz-manager seeds it from the enabled syscalls)"
fi
ncrash="$(find "$WORKDIR/crashes" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
[ "$ncrash" -eq 0 ] || ok "crashes: $ncrash existing crash dir(s) under $WORKDIR/crashes/"

# --- summary -------------------------------------------------------------
info ""
if [ "$FAILURES" -gt 0 ]; then
    die "pre-flight: $FAILURES failure(s), $WARNINGS warning(s). Fix the FAIL lines above and re-run."
fi
info "pre-flight: all checks passed, $WARNINGS warning(s)."
if [ "$MODE" = "check" ]; then
    info "(--check) not launching."
    exit 0
fi

# --------------------------------------------------------------------------
# Launch
# --------------------------------------------------------------------------
TS="$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/manager_$TS.log"
EFFECTIVE_CFG="$LOG_DIR/effective_$TS.cfg"

# Render the effective cfg: the user's cfg with workdir/syzkaller pinned to the
# absolute, possibly overridden values.  Kept next to the log as a record of
# exactly what ran.
jq --arg wd "$WORKDIR" --arg sz "$SYZKALLER" '.workdir = $wd | .syzkaller = $sz' "$CFG" >"$EFFECTIVE_CFG"

MGR_PID=""
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [ -n "$MGR_PID" ] && kill -0 "$MGR_PID" 2>/dev/null; then
        info "stopping syz-manager (pid $MGR_PID) ..."
        kill -INT "$MGR_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
            kill -0 "$MGR_PID" 2>/dev/null || break
            sleep 1
        done
        if kill -0 "$MGR_PID" 2>/dev/null; then
            warn "syz-manager did not exit on SIGINT; sending SIGTERM"
            kill -TERM "$MGR_PID" 2>/dev/null || true
        fi
    fi
    rm -f "$PIDFILE"
    exit "$rc"
}
forward() {     # forward <signal>: hand the signal to syz-manager so it tears its VMs down
    if [ -n "$MGR_PID" ] && kill -0 "$MGR_PID" 2>/dev/null; then
        kill -s "$1" "$MGR_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'forward INT' INT
trap 'forward TERM' TERM

MGR_ARGS=(-config="$EFFECTIVE_CFG")
[ "$MANAGER_DEBUG" = 1 ] && MGR_ARGS+=(-debug)
[ "${#EXTRA_ARGS[@]}" -eq 0 ] || MGR_ARGS+=("${EXTRA_ARGS[@]}")

info ""
info "== launching =="
info "command:   $MANAGER_BIN ${MGR_ARGS[*]}"
info "dashboard: http://$HTTP_HOST:$HTTP_PORT/"
info "log:       $LOG_FILE"
info "crashes:   $WORKDIR/crashes/        corpus: $WORKDIR/corpus.db"
info "vms:       ${VM_COUNT:-1} x $QEMU_BIN${MANAGER_DEBUG:+ (-debug forces 1)}"
info "stop:      Ctrl-C (or kill -INT the manager); VMs are torn down, the corpus is kept"
info ""

"$MANAGER_BIN" "${MGR_ARGS[@]}" > >(tee -a "$LOG_FILE") 2>&1 &
MGR_PID=$!
printf '%s\n' "$MGR_PID" >"$PIDFILE"

# wait is interrupted by our signal traps; loop until the manager is really gone.
rc=0
while :; do
    if wait "$MGR_PID"; then rc=0; else rc=$?; fi
    kill -0 "$MGR_PID" 2>/dev/null || break
done
MGR_PID=""

info ""
if [ "$rc" -eq 0 ] || [ "$rc" -eq 130 ]; then
    info "syz-manager exited (code $rc). Crashes: $WORKDIR/crashes/  Corpus: $WORKDIR/corpus.db  Log: $LOG_FILE"
else
    warn "syz-manager exited with code $rc; see $LOG_FILE"
fi
exit "$rc"
