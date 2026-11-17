#!/usr/bin/env bash
#
# Embargo guard (shared logic for pre-commit + pre-push).
#
# Blocks vulnerability triggers / reproducers and private working memory from
# entering git history or being pushed before the upstream fix is merged
# (responsible-disclosure embargo). This is a SAFETY NET against accidents, not
# a hard control: `git commit/push --no-verify` bypasses it by design.
#
# Tracked + shared across clones via `git config core.hooksPath githooks`
# (run githooks/install.sh once per clone). The scripts carry no embargoed
# content -- only path/name patterns (the private paths are already public in
# .gitignore) and a content sentinel assembled in two halves so the literal
# never appears here (so this dir never trips its own check).
#
set -u

mode="${1:-}"

# Private/embargoed paths (matched against repo-relative, forward-slash names).
# In this fork `.claude/` is tracked, public shared substrate (CLAUDE.md,
# onboarding, extension_overview, and the shared task registry under
# `.claude/tasks/`): see `.claude/README.md`. So `.claude/tasks/index.md`,
# `README.md` and public `<name>/CLAUDE.md` briefs are allowed; only per-user
# working memory and per-task `local/` scratch are private. The content sentinel
# below still scans every added file regardless of path.
PROTECTED_RE='^\.claude/(mptcp|maintainers|private)/|^\.claude/users/[^/]+/(tasks|notes)/|^\.claude/tasks/([^/]+/)?local/'
# Reproducer / PoC / trigger filenames, anywhere in the tree.
NAME_RE='(^|/)(repro|reproducer|poc|exploit|trigger)[^/]*\.(c|h|txt|sh|py|prog|syz)$'
# Aggregated handover / evidence exports. These are the blind spot the two
# patterns above do not cover: a numbered .md export or a dated archive carries
# no reproducer-shaped name and sits outside the private .claude paths, yet it
# collects embargoed finding descriptions and funding material in one place.
EXPORT_RE='(^|/)(_handover_export|_evidence_export|_export)/|(^|/)[^/]*(handover|handoff|evidence_export)[^/]*\.(zip|tar|tgz|tar\.gz)$'
# References to private findings. Finding numbers (and the brf-era
# NNN_<slug> directory names) only mean something next to the private records
# under .claude/private/ and .claude/tasks/; in a public commit message,
# comment or doc they tell a reader that unreported findings exist and roughly
# where. Checked in commit messages and in lines being added. Generated
# descriptions, test data and filesystem-image tests are skipped, and so are
# very long lines (compressed blobs), which keeps upstream syncs quiet.
FINDREF_RE='[Ff]indings?[ _#-]*0[0-9]{2}\b|(^|[^/0-9])0[0-9]{2}(/0[0-9]{2})+\b|\b0[0-9]{2}[-_](class|adjacent|shaped)\b|\(0[0-9]{2}(, ?0[0-9]{2})+|[a-z]/0[0-9]{2}\b|\b0[0-9]{2}_[a-z][a-z0-9]*_[a-z0-9_]+'
FINDREF_SKIP_RE='(^|/)testdata/|^sys/[^/]+/auto\.txt$|_test\.go$|^kernel_patches/|^sys/[^/]+/test/syz_mount_image_|^githooks/'

# Content sentinel -- assembled so this script does not contain the literal.
SENT='BRF-EMBARGO'; SENT="${SENT}-DO-NOT-PUSH"
ZERO=0000000000000000000000000000000000000000

violations=0
flag() { printf '  \xe2\x9c\x97 %-60s (%s)\n' "$1" "$2" >&2; violations=1; }

# Push holds. A push is the only moment when an unresolved disclosure question
# stops being hypothetical, so that is where the question gets asked -- not in a
# notes file someone has to remember to open. Two files, deliberately:
#   githooks/PUSH_HOLD      tracked, travels to every clone, content-free.
#   .git/embargo-blockers   local, never committed, carries the actual detail.
# Either one present and non-empty blocks the push.
TRACKED_HOLD="$(dirname "$0")/PUSH_HOLD"
LOCAL_HOLD="$(git rev-parse --git-dir)/embargo-blockers"

check_hold() {
  local held=0 f
  for f in "$TRACKED_HOLD" "$LOCAL_HOLD"; do
    [ -s "$f" ] || continue
    held=1
    printf '\n--- hold: %s ---\n' "$f" >&2
    sed 's/^/  /' "$f" >&2
  done
  [ "$held" -eq 0 ] && return 0
  cat >&2 <<'HOLDEOF'

==========================================================================
  EMBARGO GUARD: push held.
==========================================================================
A hold file is in place, so something listed above has to be settled
before this branch reaches a remote. The hold is not about the commits
being pushed right now; it is about state already on the branch.

To clear it:
  tracked hold   git rm githooks/PUSH_HOLD && git commit
  local hold     rm "$(git rev-parse --git-dir)/embargo-blockers"

To override deliberately, for this push only:
  git push --no-verify
==========================================================================
HOLDEOF
  exit 1
}

# Prints matching lines of a commit message read on stdin.
check_msg() {
  local where="$1" hit
  hit=$(grep -v '^#' | grep -E "$FINDREF_RE" | head -3)
  [ -n "$hit" ] && flag "$where" "private finding reference in message: $(printf '%s' "$hit" | head -1 | cut -c1-60)"
}

# Checks the lines a diff adds. Args: a git diff/show command producing -U0 output.
check_added_lines() {
  local where="$1"; shift
  local f="" line
  while IFS= read -r line; do
    case "$line" in
      "+++ b/"*) f="${line#+++ b/}" ;;
      "+++ "*) f="" ;;
      +*)
        [ -z "$f" ] && continue
        printf '%s' "$f" | grep -Eq "$FINDREF_SKIP_RE" && continue
        [ "${#line}" -gt 400 ] && continue
        printf '%s' "${line#+}" | grep -Eq "$FINDREF_RE" &&
          flag "$f$where" "private finding reference: $(printf '%s' "${line#+}" | sed 's/^[[:space:]]*//' | cut -c1-50)"
        ;;
    esac
  done < <("$@")
}

check_path() {
  local f="$1"
  printf '%s' "$f" | grep -Eq "$PROTECTED_RE" && flag "$f" "private/embargoed path"
  printf '%s' "$f" | grep -Eq "$NAME_RE"      && flag "$f" "reproducer/PoC filename"
  printf '%s' "$f" | grep -Eq "$EXPORT_RE"    && flag "$f" "aggregated handover/evidence export"
}

case "$mode" in
  pre-commit)
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      check_path "$f"
      git show ":$f" 2>/dev/null | grep -qF "$SENT" && flag "$f" "embargo sentinel in content"
    done < <(git diff --cached --name-only --diff-filter=AM)
    check_added_lines "" git diff --cached -U0 --diff-filter=AM
    ;;
  commit-msg)
    check_msg "commit message" < "${2:?commit-msg needs the message file}"
    ;;
  pre-push)
    check_hold
    remote="${2:-origin}"
    while read -r _lref lsha _rref rsha; do
      [ "$lsha" = "$ZERO" ] && continue   # branch deletion
      if [ "$rsha" = "$ZERO" ]; then
        commits=$(git rev-list "$lsha" --not --remotes="$remote")
      else
        commits=$(git rev-list "$rsha..$lsha")
      fi
      # Commits already on any remote (e.g. upstream syzkaller) are not ours
      # to police for finding references.
      ours=$(git rev-list "$lsha" --not --remotes)
      for c in $commits; do
        if printf '%s\n' "$ours" | grep -qx "$c"; then
          check_msg "message @ ${c:0:12}" < <(git log -1 --format=%B "$c")
          check_added_lines " @ ${c:0:12}" git show -U0 --format= "$c"
        fi
        while IFS= read -r f; do
          [ -z "$f" ] && continue
          check_path "$f"
          if git cat-file -e "$c:$f" 2>/dev/null; then
            git show "$c:$f" 2>/dev/null | grep -qF "$SENT" && flag "$f @ ${c:0:12}" "embargo sentinel in content"
          fi
        done < <(git diff-tree --no-commit-id --name-only -r "$c")
      done
    done
    ;;
  *)
    echo "embargo_guard: unknown mode '$mode'" >&2
    exit 0
    ;;
esac

if [ "$violations" -ne 0 ]; then
  bypass=$([ "$mode" = pre-push ] && echo "push" || echo "commit")
  cat >&2 <<EOF

==========================================================================
  EMBARGO GUARD: blocked this ${mode}.
==========================================================================
The item(s) above are vulnerability triggers/reproducers, private working
memory, or references to private findings, which must NOT enter git history or
reach a remote (the fork is public). Reword a finding reference to say what the
code does, without the finding number.

If you are certain this is a false positive, bypass deliberately:
    git ${bypass} --no-verify
Pushing a pre-embargo reproducer is irreversible -- be sure.
==========================================================================
EOF
  exit 1
fi
exit 0
