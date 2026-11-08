# githooks/ -- embargo guard

Tracked git hooks that act as a **responsible-disclosure safety net**: they
block committing or pushing vulnerability triggers / reproducers and private
working memory before the corresponding upstream fix is merged.

This is collaborative tooling for the fork, not a secret: the scripts carry no
embargoed data. They match (a) private-dir paths that are already declared in
the repo `.gitignore`, (b) generic reproducer/PoC filename patterns, and (c) a
short content sentinel (assembled at runtime so the literal never appears in
the source -- which is also why this directory never trips its own checks).

## Activate (once per clone)

```sh
./githooks/install.sh        # sets core.hooksPath -> githooks/
```

Cloning does **not** auto-activate hooks (git never runs hooks from a fresh
clone until `core.hooksPath` is set), so each collaborator runs this once.

## What it blocks

| Layer | pre-commit | pre-push |
|-------|-----------|----------|
| private/embargoed paths (`.claude/tasks`, `.claude/mptcp`, `.claude/maintainers`, `.claude/private`, `.claude/users/*/tasks\|notes`) | staged files | pushed commit range |
| reproducer/PoC/trigger filenames (`repro*`, `poc*`, `exploit*`, `trigger*`) | staged files | pushed commit range |
| content sentinel (catches a reproducer copied out into a tracked path) | staged blobs | blobs in pushed commits |
| aggregated handover/evidence export (`_handover_export/`, dated handover archives) | staged paths | paths in pushed commits |

## Push holds

A push is the only moment when an unresolved disclosure question stops being
hypothetical, so that is where the question gets asked, rather than in a notes
file someone has to remember to open. `pre-push` refuses while either hold file
is present and non-empty:

| file | tracked? | carries |
|---|---|---|
| `githooks/PUSH_HOLD` | yes, travels to every clone | that a hold exists and where to look. No detail: it is public. |
| `.git/embargo-blockers` | no, cannot be committed | the actual item list and each item's status. |

The split is the point. The fact of a hold has to travel, because a fresh clone
pushing the same branch carries the same hazard. The content must not travel,
because naming an unreported finding in a tracked file is the leak it is meant
to prevent.

Clear the tracked hold with `git rm githooks/PUSH_HOLD` in its own commit, and
the local one by deleting the file. `git push --no-verify` overrides both, for
one push, deliberately.

## Limits (be honest about these)

- `git commit/push --no-verify` bypasses all hooks. The guard stops *accidents*,
  not a determined push.
- Hooks are inert until `install.sh` runs in a given clone.
- The primary protection is still `.gitignore`; this is defense-in-depth.

## Where embargoed artefacts live

Reproducers and crash logs stay under `.claude/tasks/.../findings/<NNN>_*/`
(gitignored). Add a sentinel comment line to any sensitive file as a backstop
for the content-scan layer.
