# Task system

A lightweight task registry for this fork, modeled on the convention used in our
Linux kernel working tree.

## How it works

- `index.md` is the single source of truth: one entry per open thread, with a
  `status`, a `brief` pointer, a `goal`, and `keywords` for routing. It is small
  and is read at the start of every session.
- A thread that grows its own detailed brief gets a directory here,
  `tasks/<name>/`, with a `CLAUDE.md` brief; until then its `brief:` field
  points at the doc that already covers it (an `extension_overview.md` section, a
  `docs/` reference, a tool `README.md`).
- Claude mentions a matching task and **asks before loading** its brief, rather
  than auto-loading.

## Shared vs. per-user

- **Tracked (shared, public):** `index.md`, this `README.md`, and any
  `tasks/<name>/CLAUDE.md` brief that is a clean engineering description.
- **Not tracked (per-user working memory):** personal scratch, in-progress
  notes, and anything under `.claude/users/<you>/`. These are gitignored so
  collaborators do not step on each other's working state. Keep private or
  unpublished material out of tracked briefs (see `../../CLAUDE.md`,
  "Public-repo discipline").

## Adding a task

1. Add an entry to `index.md` with the four fields.
2. If it needs more than a few lines, create `tasks/<name>/CLAUDE.md` and point
   `brief:` at it.
3. Keep it public-safe: capability and plan, not vulnerability detail.
