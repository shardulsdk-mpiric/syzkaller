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

## Limits (be honest about these)

- `git commit/push --no-verify` bypasses all hooks. The guard stops *accidents*,
  not a determined push.
- Hooks are inert until `install.sh` runs in a given clone.
- The primary protection is still `.gitignore`; this is defense-in-depth.

## Where embargoed artefacts live

Reproducers and crash logs stay under `.claude/tasks/.../findings/<NNN>_*/`
(gitignored). Add a sentinel comment line to any sensitive file as a backstop
for the content-scan layer.
