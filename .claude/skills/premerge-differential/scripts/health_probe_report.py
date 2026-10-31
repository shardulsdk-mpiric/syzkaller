#!/usr/bin/env python3
"""Turn what health_probe.sh collected into report.md + per_call.csv.

Reads RAW_DIR (layout written by health_probe.sh):
  status, params          key=value
  sample/*                the replayed programs (syzlang text)
  vm/execprog.log         syz-execprog -debug -vv 1 -output, stdout+stderr
  vm/execprog.rc          exit code of the run inside the VM
  vm/dmesg.{before,after} vm/proc_net.{before,after} (/proc/net/netstat + snmp)
  vm/execns/<netns inode>  last netstat + snmp snapshot of each executor netns
  vm/uname.txt  serial.log

Writes OUT_DIR/report.md, OUT_DIR/per_call.csv, OUT_DIR/dmesg_new.txt,
OUT_DIR/executor_other.txt.

Usage: health_probe_report.py --raw RAW_DIR --out OUT_DIR
                              [--counter-regex RE] [--must-succeed RE]
Exit: 0 healthy | 2 VM never answered | 3 a --must-succeed call had zero
successes (or the regex matched no call) | 4 SYZFAIL in executor output.

Run with `python3 -I`; stdlib only. Usable on its own against any directory in
the raw layout, which is how its parsers are tested without a VM.

What the parsers key on (fork at the commit the probe was written against):
  executor/executor.cc execute_call(): debug("#%d [%llums] -> %s(") and
    debug("#%d [%llums] <- %s=0x%llx") + optional " errno=%d" (res == -1 only),
    " cover=%u"; debug() prints only under -debug (flag_debug).
  executor/executor.cc failmsg(): "SYZFAIL: <err>" then " (errno N: ...)".
  tools/syz-execprog/execprog.go printCallResults(): log level 1 line
    "CALL i: signal S, coverage C errno E[ unfinished][ blocked][ faulted]";
    Next(): "executing program:\\n<prog>" under -output;
    getProgramIndex(): "executed programs: N".
  pkg/rpcserver/rpcserver.go printMachineCheck(): "disabled the following
    syscalls:" / "transitively disabled the following syscalls ..." blocks.
"""
import argparse
import collections
import csv
import errno as errno_mod
import os
import re
import sys

RE_GOLOG = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d ")
RE_CALL_IN = re.compile(r"#(\d+) \[(\d+)ms\] -> ([^\s(]+)\(")
RE_CALL_OUT = re.compile(r"#(\d+) \[(\d+)ms\] <- ([^\s=]+)=0x([0-9a-f]+)")
RE_ERRNO = re.compile(r" errno=(\d+)")
RE_EXEC_OPTS = re.compile(r"\[\d+ms\] exec opts: reqid=(\d+)")
RE_EP_CALL = re.compile(r"CALL (\d+): signal (\d+), coverage (\d+) errno (\d+)((?: \w+)*)\s*$")
RE_EP_EXECUTED = re.compile(r"executed programs: (\d+)")
RE_PROG_LINE = re.compile(r"^(?:r\d+ = )?([A-Za-z0-9_$]+)\(")
RE_SYZFAIL = re.compile(r"\bSYZFAIL: ")
RE_ORPHAN = re.compile(r"^\s*(errno=\d+|cover=\d+|fault=\d+|rerun=\d+)(\s|$)")  # tail of a split "<-" line
RE_MC_HEAD = re.compile(r"(transitively )?disabled the following syscalls")
RE_MC_LINE = re.compile(r"^(\S+)\s+: (.*)$")
RE_DMESG_TS = re.compile(r"^\[\s*\d+\.\d+\] ")
RE_DMESG_FLAG = re.compile(
    r"WARNING:|BUG:|KASAN|KCSAN|KMSAN|UBSAN|kernel panic|Call Trace:|RIP: |"
    r"general protection|Oops|INFO: task .* blocked|rcu: INFO|stall|hung task|"
    r"refcount_t|list_del corruption|memory leak|unregister_netdevice|"
    r"page allocation failure|Out of memory|soft lockup|SYZFAIL")
FAILED_RES = "ffffffffffffffff"  # res == -1 on amd64


def read_kv(path):
    d = {}
    if os.path.exists(path):
        with open(path, errors="replace") as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    d[k] = v
    return d


def read_lines(path):
    if not os.path.exists(path):
        return None
    with open(path, errors="replace") as f:
        return f.read().splitlines()


def errname(n):
    if n == 0:
        return "ok"
    if n == 999:
        return "notexec"  # runner.go pads unexecuted calls with Error 999
    return errno_mod.errorcode.get(n, "E?")


# --- sample programs ----------------------------------------------------------
def parse_sample(sample_dir):
    """call -> (programs containing it, call sites)."""
    progs, sites = collections.Counter(), collections.Counter()
    nprogs = 0
    if not os.path.isdir(sample_dir):
        return nprogs, progs, sites
    for name in sorted(os.listdir(sample_dir)):
        lines = read_lines(os.path.join(sample_dir, name)) or []
        nprogs += 1
        seen = set()
        for line in lines:
            m = RE_PROG_LINE.match(line)
            if m:
                sites[m.group(1)] += 1
                seen.add(m.group(1))
        for c in seen:
            progs[c] += 1
    return nprogs, progs, sites


# --- execprog.log -------------------------------------------------------------
class CallStat:
    __slots__ = ("started", "finished", "success", "failed", "errnos", "errno_unknown")

    def __init__(self):
        self.started = self.finished = self.success = self.failed = self.errno_unknown = 0
        self.errnos = collections.Counter()


def parse_execprog_log(lines):
    r = {
        "calls": collections.defaultdict(CallStat),
        "exec_opts": 0,            # programs the executor started (-debug marker)
        "progs_dumped": 0,         # "executing program:" blocks (-output)
        "executed_programs": 0,    # max of execprog's periodic counter
        "ep_calls": 0, "ep_finished": 0, "ep_blocked": 0, "ep_unfinished": 0,
        "ep_errnos": collections.Counter(),
        "syzfail": [],             # (line, following line)
        "machine_check": [],       # (kind, call, reason)
        "other": [],               # everything else the executor/harness printed
        "golog_other": [],         # execprog log lines that are not CALL/executed/dump
        "split_lines": 0,          # orphan " errno=N" tails of "<-" lines split by another proc
    }
    if lines is None:
        return r
    calls = r["calls"]
    in_dump = False
    mc_kind = None
    skip_next = False
    for i, line in enumerate(lines):
        if not line.strip():
            mc_kind = None
            continue
        if RE_GOLOG.match(line):
            body = RE_GOLOG.sub("", line)
            in_dump = body.startswith("executing program:")
            mc_kind = None
            if in_dump:
                r["progs_dumped"] += 1
                continue
            m = RE_EP_CALL.search(body)
            if m:
                r["ep_calls"] += 1
                e = int(m.group(4))
                flags = m.group(5)
                if "unfinished" in flags:
                    r["ep_unfinished"] += 1
                else:
                    r["ep_finished"] += 1
                if "blocked" in flags:
                    r["ep_blocked"] += 1
                r["ep_errnos"][e] += 1
                continue
            m = RE_EP_EXECUTED.search(body)
            if m:
                r["executed_programs"] = max(r["executed_programs"], int(m.group(1)))
                continue
            m = RE_MC_HEAD.search(body)
            if m:
                mc_kind = "transitively-disabled" if m.group(1) else "disabled"
                continue
            r["golog_other"].append(body)
            continue
        if mc_kind:
            m = RE_MC_LINE.match(line)
            if m:
                r["machine_check"].append((mc_kind, m.group(1), m.group(2)))
                continue
            mc_kind = None
        if skip_next:
            skip_next = False
            continue
        if RE_EXEC_OPTS.search(line):
            r["exec_opts"] += 1
            in_dump = False
            continue
        # A line can hold both a "<-" and, when another proc's write landed
        # mid-line, a "->" of a different call: count every piece present.
        m_out = RE_CALL_OUT.search(line)
        if m_out:
            in_dump = False
            st = calls[m_out.group(3)]
            st.finished += 1
            if m_out.group(4) == FAILED_RES:
                st.failed += 1
                tail = line[m_out.end():]
                m_in = RE_CALL_IN.search(tail)
                em = RE_ERRNO.search(tail[: m_in.start()] if m_in else tail)
                if em:
                    st.errnos[int(em.group(1))] += 1
                else:
                    st.errno_unknown += 1
            else:
                st.success += 1
        for m_in in RE_CALL_IN.finditer(line):
            in_dump = False
            calls[m_in.group(3)].started += 1
            m_out = m_out or m_in
        if m_out:
            continue
        if RE_ORPHAN.match(line):
            r["split_lines"] += 1
            continue
        if RE_SYZFAIL.search(line):
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            r["syzfail"].append((line, nxt))
            skip_next = nxt.lstrip().startswith("(errno ")
            continue
        if in_dump and RE_PROG_LINE.match(line):
            continue
        r["other"].append(line)
    return r


def group_other(lines, top=40):
    """Collapse numbers so repeated diagnostics group; keep one example each."""
    norm = collections.Counter()
    example = {}
    for line in lines:
        key = re.sub(r"0x[0-9a-fA-F]+", "0xH", line)
        key = re.sub(r"\d+", "N", key)
        norm[key] += 1
        example.setdefault(key, line)
    return [(cnt, example[k]) for k, cnt in norm.most_common(top)]


# --- dmesg --------------------------------------------------------------------
def dmesg_new(before, after):
    if after is None:
        return None
    before = before or []
    if after[: len(before)] == before:
        return after[len(before):]
    strip = lambda ls: collections.Counter(RE_DMESG_TS.sub("", x) for x in ls)
    b = strip(before)
    out = []
    for line in after:
        k = RE_DMESG_TS.sub("", line)
        if b[k] > 0:
            b[k] -= 1
        else:
            out.append(line)
    return out


# --- counters -----------------------------------------------------------------
def parse_proc_net(lines):
    """/proc/net/netstat + /proc/net/snmp -> {ProtoKey: int}, nstat naming."""
    d = {}
    if not lines:
        return d
    i = 0
    while i + 1 < len(lines):
        h, v = lines[i], lines[i + 1]
        hp, _, hk = h.partition(":")
        vp, _, vv = v.partition(":")
        if hp and hp == vp:
            keys, vals = hk.split(), vv.split()
            for k, x in zip(keys, vals):
                try:
                    d[hp + k] = int(x)
                except ValueError:
                    pass
            i += 2
        else:
            i += 1
    return d


def counter_deltas(before, after, regex):
    rx = re.compile(regex)
    rows, matched = [], 0
    for k in sorted(after):
        if not rx.search(k):
            continue
        matched += 1
        dv = after[k] - before.get(k, 0)
        if dv:
            rows.append((k, before.get(k, 0), after[k], dv))
    return matched, rows


# --- report -------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--counter-regex", default="MPTcp|Tcp")
    ap.add_argument("--must-succeed", default="")
    a = ap.parse_args()
    raw, out = a.raw, a.out
    os.makedirs(out, exist_ok=True)
    vm = os.path.join(raw, "vm")

    status = read_kv(os.path.join(raw, "status"))
    params = read_kv(os.path.join(raw, "params"))
    vm_answered = status.get("vm_answered") == "1"
    nprogs, s_progs, s_sites = parse_sample(os.path.join(raw, "sample"))
    log = parse_execprog_log(read_lines(os.path.join(vm, "execprog.log")))
    rc_lines = read_lines(os.path.join(vm, "execprog.rc")) or []
    execprog_rc = rc_lines[0].strip() if rc_lines else "n/a"
    uname = (read_lines(os.path.join(vm, "uname.txt")) or ["n/a"])[0]
    dnew = dmesg_new(read_lines(os.path.join(vm, "dmesg.before")), read_lines(os.path.join(vm, "dmesg.after")))
    serial = read_lines(os.path.join(raw, "serial.log")) or []
    cb = parse_proc_net(read_lines(os.path.join(vm, "proc_net.before")))
    ca = parse_proc_net(read_lines(os.path.join(vm, "proc_net.after")))
    n_matched, deltas = counter_deltas(cb, ca, a.counter_regex)
    # Executor netns counters: each netns starts at zero, so the sum of their
    # last snapshots is what the programs moved.
    ens = {}
    ens_dir = os.path.join(vm, "execns")
    ens_files = sorted(f for f in os.listdir(ens_dir) if not f.startswith(".")) if os.path.isdir(ens_dir) else []
    for f in ens_files:
        for k, v in parse_proc_net(read_lines(os.path.join(ens_dir, f))).items():
            ens[k] = ens.get(k, 0) + v
    e_matched, e_deltas = counter_deltas({}, ens, a.counter_regex)

    calls = log["calls"]
    names = sorted(set(calls) | set(s_progs))
    never_ok = [c for c in names if calls[c].success == 0] if calls else names
    must_fail, must_matched = [], []
    if a.must_succeed:
        mrx = re.compile(a.must_succeed)
        must_matched = [c for c in names if mrx.search(c)]
        must_fail = [c for c in must_matched if calls[c].success == 0]

    # verdict
    reasons, warns = [], []
    code = 0
    if not vm_answered:
        code = 2
        reasons.append("VM never answered ssh" + (" (qemu exited early)" if status.get("qemu_exited_early") else ""))
    elif log["syzfail"]:
        code = 4
        reasons.append("SYZFAIL in executor output (%d)" % len(log["syzfail"]))
    if a.must_succeed and code == 0:
        if not must_matched:
            code = 3
            reasons.append("--must-succeed %r matched no call in sample or log" % a.must_succeed)
        elif must_fail:
            code = 3
            reasons.append("must-succeed calls with zero successes: " + ", ".join(must_fail))
    if vm_answered and status.get("copy_in") == "0":
        warns.append("copying executor/sample into the VM failed")
    if vm_answered and status.get("collected") == "0":
        warns.append("no execprog.log came back from the VM (died mid-run? see serial.log)")
    if execprog_rc not in ("0", "n/a"):
        warns.append("execprog exit code %s%s" % (execprog_rc, " (run-timeout hit)" if execprog_rc in ("124", "137") else ""))
    if nprogs and log["exec_opts"] < nprogs:
        warns.append("executor started %d programs of %d sampled" % (log["exec_opts"], nprogs))
    if never_ok:
        warns.append("%d call(s) never succeeded" % len(never_ok))
    flagged = [l for l in (dnew or []) if RE_DMESG_FLAG.search(l)]
    # The serial log also holds boot; it is the evidence only when the run's
    # own dmesg never came back (VM silent, or died mid-run).
    serial_is_evidence = not vm_answered or status.get("collected") == "0"
    sflagged = [l for l in serial if RE_DMESG_FLAG.search(l)] if serial_is_evidence else []
    if flagged:
        warns.append("%d flagged new dmesg line(s)" % len(flagged))
    if vm_answered and ca and not deltas:
        warns.append("no counter matching %r moved" % a.counter_regex)
    if log["golog_other"]:
        bad = [l for l in log["golog_other"] if re.search(r"failed|lost connection|error|panic", l, re.I)]
        if bad:
            warns.append("execprog reported: " + bad[0][:120])

    # per_call.csv
    with open(os.path.join(out, "per_call.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["call", "sample_programs", "sample_sites", "started", "finished", "success",
                    "failed", "errno_unknown", "errnos"])
        for c in names:
            st = calls[c] if c in calls else CallStat()
            errs = ";".join("%d(%s):%d" % (e, errname(e), n) for e, n in sorted(st.errnos.items()))
            w.writerow([c, s_progs.get(c, 0), s_sites.get(c, 0), st.started, st.finished,
                        st.success, st.failed, st.errno_unknown, errs])
    with open(os.path.join(out, "dmesg_new.txt"), "w") as f:
        f.write("\n".join(dnew or []) + ("\n" if dnew else ""))
    with open(os.path.join(out, "executor_other.txt"), "w") as f:
        f.write("\n".join(log["other"]) + ("\n" if log["other"] else ""))

    R = []
    p = R.append
    p("# Campaign health probe")
    p("")
    p("**Verdict: %s (exit %d)**" % ("HEALTHY" if code == 0 else "FAIL", code))
    for x in reasons:
        p("- FAIL: " + x)
    for x in warns:
        p("- WARN: " + x)
    if code == 0 and not warns:
        p("- every sampled call succeeded at least once, no SYZFAIL, no flagged dmesg lines")
    p("")
    p("## Parameters")
    p("")
    for k in ("started_utc", "syz_bin", "syz_bin_sha256sums", "kernel", "image", "corpus", "n", "cpu", "mem",
              "cmdline", "sandbox", "procs", "threaded", "slowdown", "execprog_extra", "counter_regex",
              "must_succeed", "ssh_timeout", "run_timeout", "qemu"):
        if k in params:
            p("- %s: `%s`" % (k, params[k]))
    p("")
    p("## VM")
    p("")
    p("- answered ssh: %s%s" % ("yes" if vm_answered else "NO",
                                 " after %s s" % status["boot_wait_s"] if "boot_wait_s" in status else ""))
    p("- guest: `%s`" % uname)
    p("- execprog exit code: %s; run wall time: %s s" % (execprog_rc, status.get("run_s", "n/a")))
    p("- sample: %s of %s corpus programs (every %s-th)" % (status.get("sampled", nprogs),
                                                             status.get("corpus_total", "?"),
                                                             status.get("sample_step", "?")))
    p("")
    p("## Programs and calls")
    p("")
    p("- executor started %d programs (`exec opts` markers); execprog dumped %d; "
      "execprog counter reached %d" % (log["exec_opts"], log["progs_dumped"], log["executed_programs"]))
    p("- execprog CALL lines: %d executed, %d finished, %d unfinished, %d blocked" %
      (log["ep_calls"], log["ep_finished"], log["ep_unfinished"], log["ep_blocked"]))
    if log["split_lines"]:
        p("- %d executor result line(s) were split by another proc's output "
          "(errno lost for those; use --procs 1)" % log["split_lines"])
    if log["ep_errnos"]:
        p("- execprog errno histogram (all calls): " + ", ".join(
            "%d(%s)=%d" % (e, errname(e), n) for e, n in sorted(log["ep_errnos"].items())))
    p("")
    p("| call | sample progs | started | ok | fail | errno (name:count) |")
    p("|------|-------------:|--------:|---:|-----:|---------------------|")
    for c in names:
        st = calls[c] if c in calls else CallStat()
        errs = ", ".join("%s:%d" % (errname(e), n) for e, n in sorted(st.errnos.items()))
        if st.errno_unknown:
            errs += (", " if errs else "") + "unknown:%d" % st.errno_unknown
        p("| `%s` | %d | %d | %d | %d | %s |" % (c, s_progs.get(c, 0), st.started, st.success, st.failed, errs))
    p("")
    p("### Calls that never succeeded")
    p("")
    if never_ok:
        for c in never_ok:
            st = calls[c] if c in calls else CallStat()
            why = "never started" if st.started == 0 else "failed %d/%d" % (st.failed, st.finished)
            p("- `%s`: %s" % (c, why))
    else:
        p("- none")
    if a.must_succeed:
        p("")
        p("must-succeed `%s` matched %d call(s); zero-success: %s" %
          (a.must_succeed, len(must_matched), ", ".join("`%s`" % c for c in must_fail) or "none"))
    p("")
    p("## SYZFAIL")
    p("")
    if log["syzfail"]:
        for l1, l2 in log["syzfail"][:20]:
            p("- `%s` `%s`" % (l1.strip(), l2.strip()))
    else:
        p("- none")
    p("")
    p("## Machine check (calls execprog disabled before running)")
    p("")
    if log["machine_check"]:
        for kind, c, why in log["machine_check"]:
            p("- %s `%s`: %s" % (kind, c, why))
    else:
        p("- none reported")
    p("")
    p("## Executor / harness output (not call traces; grouped, numbers collapsed)")
    p("")
    p("%d line(s); full text in `executor_other.txt`." % len(log["other"]))
    p("")
    for cnt, ex in group_other(log["other"]):
        p("- %5d x `%s`" % (cnt, ex.strip()[:160]))
    if log["golog_other"]:
        p("")
        p("execprog's own messages (excluding CALL/executed/dump):")
        p("")
        for l in log["golog_other"][:30]:
            p("- `%s`" % l.strip()[:160])
    p("")
    p("## Kernel log")
    p("")
    if dnew is None:
        p("- no dmesg.after collected")
    else:
        p("- %d new line(s) during the run (`dmesg_new.txt`); %d flagged" % (len(dnew), len(flagged)))
        for l in flagged[:40]:
            p("- FLAG `%s`" % l.strip()[:200])
    if sflagged:
        p("- serial console flagged lines (%d):" % len(sflagged))
        for l in sflagged[:40]:
            p("  - `%s`" % l.strip()[:200])
    if not vm_answered or status.get("collected") == "0":
        p("")
        p("serial console tail:")
        p("")
        p("```")
        R.extend(serial[-40:])
        p("```")
    p("")
    p("## Protocol counters (`%s`)" % a.counter_regex)
    p("")
    p("### Executor netns (what the programs moved)")
    p("")
    if not ens_files:
        p("- no executor netns snapshot collected (procs ran in the init netns, or none lived 2 s)")
    else:
        p("- %d netns sampled; %d counters match; %d non-zero" % (len(ens_files), e_matched, len(e_deltas)))
        p("")
        p("| counter | total |")
        p("|---------|------:|")
        for k, b, c, d in e_deltas:
            p("| `%s` | %d |" % (k, c))
    p("")
    p("### Init netns (the VM itself: ssh, setup)")
    p("")
    if not ca:
        p("- no counter snapshot collected")
    else:
        p("- %d counters match; %d moved" % (n_matched, len(deltas)))
        p("")
        p("| counter | before | after | delta |")
        p("|---------|-------:|------:|------:|")
        for k, b, c, d in deltas:
            p("| `%s` | %d | %d | %+d |" % (k, b, c, d))
    p("")
    p("## Files")
    p("")
    p("- `per_call.csv`, `dmesg_new.txt`, `executor_other.txt` next to this report")
    p("- raw: `raw/vm/execprog.log` (full trace), `raw/serial.log`, `raw/qemu.cmd`, "
      "`raw/remote.sh`, `raw/sample.list`, `raw/status`, `raw/params`")
    with open(os.path.join(out, "report.md"), "w") as f:
        f.write("\n".join(R) + "\n")
    print("report: %s (exit %d)" % (os.path.join(out, "report.md"), code))
    for x in reasons:
        print("FAIL: " + x)
    for x in warns:
        print("WARN: " + x)
    sys.exit(code)


if __name__ == "__main__":
    main()
