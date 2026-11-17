# .claude/ -- working context for this fork

This directory is the shared working context for Claude Code (and humans) in
this fork of Syzkaller. It is **tracked and public**: it exists to help a
collaborator get started and understand the protocol-flow extension, so keep it
a clean engineering artifact (no vulnerability detail, reproducers, or private
notes -- see `../CLAUDE.md`, "Public-repo discipline").

## Layout

| path | what it is |
|---|---|
| `../CLAUDE.md` | top-level: fork identity, attribution, what's ours, how to work. Auto-loaded by Claude Code. |
| `ONBOARDING.md` | get set up, build, run a campaign, contribute. Start here. |
| `extension_overview.md` | the architecture of the extension (state carriers, surfaces, keystones, struct_ops, diff, corpus). |
| `tasks/index.md` | the task registry: open development and usage threads. Read at session start. |
| `tasks/README.md` | the task-system convention. |

The detailed per-surface references live under `docs/` (e.g.
`docs/linux/mptcp_protocol_fuzzing.md`), beside syzkaller's own docs, not here.

## Session contract

1. `../CLAUDE.md` auto-loads.
2. Read `tasks/index.md` (small, always).
3. When a request matches a task's keywords, mention it and **ask before
   loading** that task's brief.

## Private area: `.claude/private/`

Everything that must not be public lives under `.claude/private/`, which is
gitignored (tracked rule in `../.gitignore`) and blocked by `githooks/`. Suggested layout:

| path | what it is |
|---|---|
| `private/findings/<NNN>_<slug>/` | one directory per finding: report, reproducers, triage, disclosure status |
| `private/findings/index.md` | the finding list and each finding's disclosure state |
| `private/maintainers/` | drafts of and notes on maintainer correspondence |
| `private/handovers/` | handover and evidence exports (funding, grant material) |

Finding numbers are private identifiers. They may appear only under
`.claude/private/` and in private task briefs, never in commit messages,
comments, docs or test names.

## What is tracked

Tracked (shared substrate): `../CLAUDE.md`, this `README.md`, `ONBOARDING.md`,
`extension_overview.md`, `tasks/index.md`, `tasks/README.md`.

Not tracked (per-user / per-machine working state, gitignored): any
`.claude/users/`, per-task working directories, scratch notes, and
`.claude/settings.local.json`. See `tasks/README.md`.
