# Run record

Private, outside any repository (run data can hold crash reports/reproducers).

```
<run-root>/<campaign>/
  README.md            layout + manifest template (copy this file's template)
  RUNS.md              append-only ledger: one row per run, VOID runs included
  series/
    SELECTION.md       dated in/out decisions, reason + lore link per series
    series.json candidates.tsv apply_check.tsv fail_analysis.txt
    mbox/<id>.mbox     pinned inputs
    rebased_unreviewed/ hand rebases awaiting the user's review
  runs/<YYYYMMDD>-<machine>-<group>-<n>/
    manifest.md base.cfg patched.cfg diffrepro.log out/ corpus_in.db corpus_out.db
```

Ledger columns: run-id | machine | group | base commit | patched commit |
syzkaller rev | duration | verdict | findings.

## Manifest template

```
run-id / machine / started-ended (UTC) / duration flags / VM counts (cpu, mem)
group:
base: export tip, keystone (fork commit), .config sha256
patched: branch+commit; series in apply order: id, version, msgid, mbox sha256; rebased patches
sanitizers:
syzkaller rev (diffrepro == executor):
enabled syscalls: file + hash; notable knobs
VM image sha256:
canary: pass/fail + evidence
health snapshots:
corpus in (source, merged how) / out (size):
results: patched-only / unresolved / possibly / affects-both
findings: pointers + the user's disposition
notes:
```
