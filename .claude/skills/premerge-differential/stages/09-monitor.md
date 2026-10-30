# Stage 9: Monitor

Check on a schedule (first at +30 min, then every few hours), proactively, not
only at the end.

Health signals that work: qemu %CPU high, "executed programs"/exec total and
coverage rising in the log, boot errors not accumulating. Signals that do NOT
work: process count, free RAM (both look fine in a boot loop), and — until the
engine persists its corpus — `corpus.db` size.

Crashes:
- Read the driver's summary buckets: PATCHED-ONLY (reproduced, base clean),
  UNRESOLVED (repro found, no base verdict: replay on base by hand), POSSIBLY
  (seen often on patched only, no repro), AFFECTS-BOTH (not ours).
- A patched-only crash with no repro is a candidate, not a result. Before
  calling it series-caused, check whether the code that fires (e.g. a WARN) is
  already in base: unequal VM counts and rare races produce false
  "patched-only". Escalate with the `crash-reproducer` skill (syz-crush mass
  replay, then syz-repro), and replay on base.
- **No repro is not a verdict.** A crash that failed to reproduce (or
  reproduced at reliability 0) is looked up before it is set aside: read the
  stacks. Generic-kernel noise (no frame in the protocol or the series' hunks)
  gets a one-line triage in the manifest. In-scope ones go on a work list and
  are built up to something maintainers will take seriously (hard races get
  deprioritised on the list): syz-crush mass replay, a targeted program,
  widening the race window (more vCPUs, KCSAN delays), an explanation of the
  interleaving from the code.
- Disposition of a finding (real, which series, report or not) is the user's.
  Never post to a list from here.

Record health snapshots and every crash's triage state in the manifest.

## Watchers (set up for every long run)

1. **On the fuzzing host**, next to the run: `setsid nohup bash watch_run.sh <run-dir>`
   (kept in the campaign's run record). It survives the controlling session
   and appends `<run-dir>/events.log` every 2 min: NEWTITLE (first crash per
   title and side), REPRO (repro found/failed, patched-only, unresolved),
   BUCKET (a non-empty patched-only/contested/unresolved/possibly bucket),
   ERROR (SYZFAIL, lost connection, no output, run failed), STALL (patched
   exec flat 20 min), DEAD/ENDED (driver gone), and hourly HEALTH.
2. **In the session**: a Monitor that ssh-tails `runs/*/events.log` and
   filters out HEALTH. Monitors expire (30 min max): re-arm on expiry, and
   after starting a new run (the tail glob is fixed at start).
3. On each event: NEWTITLE on base only = suppression, note it; NEWTITLE on
   patched = watch for its repro; BUCKET / REPRO patched-only = triage per
   the list above and tell the user; DEAD / STALL / ERROR = diagnose now.
