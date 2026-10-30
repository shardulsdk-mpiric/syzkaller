# Stage 2: Intake (what is in review right now)

Goal: the full list of series in review, each with a lore link, with every
filter stated out loud.

```
python3 -I scripts/pw_intake.py <rec>/series --project <pw-id> --list <lore-list> \
    --since <YYYY-MM-DD> --exclude-author "<name>" ...
```
(MPTCP: project 405, list `mptcp`.) Produces `series.json`, `candidates.tsv`,
`mbox/`, `meta/`.

Rules:
- **Source limits, say them:** patchwork covers one list. A series sent only to
  netdev will be missing; patchwork states can be wrong both ways.
- **Date cutoff is a filter, not a fact.** The script prints how many pending
  series are older than `--since`. Run `staleness.py` on the recent-but-older
  ones (e.g. same year) instead of ignoring them; years-old entries can be
  treated as dead in bulk, with a line in SELECTION.md saying so.
- **Exclusions** (the user's own and their teammates' series) go in
  SELECTION.md by name, with the date the rule was set.
- **Latest version per series** is grouped by title; a v-bump with a renamed
  title escapes the grouping (seen: "unify entry free path" v3 → "fix entry
  free path" v4). Skim for same-author near-duplicate titles.
- Not every patchwork "series" is a patch: bug reports and replies get filed as
  series. They show `no-diff` in apply_check.

Then:
```
scripts/apply_check.sh <kernel-repo> <campaign>-base <rec>/series
python3 -I scripts/staleness.py <rec>/series <kernel-repo> net-next/main <maint>/<tip> \
    --ids <comma list> [--stale-days 60]
```
staleness output is evidence: open each credit/subject hit before calling a
series concluded (review trailers are noise). Patchwork's per-patch comment
count misses replies to a cover letter; for the decision, take last activity
from the whole thread: `b4 -q mbox -n <id>.mbx -o <dir> <msgid>`, then the
latest Date among messages not from the author or a bot (CI, sashiko). Read the
human replies on changes-requested series: "wait for the discussion to settle"
means defer; a request that only extends the fix is small enough to keep.

Staleness rule in force (set by the user, revisit on anomalies): drop if no
activity for > 60 days; changes-requested -> defer unless the requested change
is small.

Output: SELECTION.md tables, every row with its lore link.
