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
PROTECTED_RE='^\.claude/(tasks|mptcp|maintainers|private)/|^\.claude/users/[^/]+/(tasks|notes)/'
# Reproducer / PoC / trigger filenames, anywhere in the tree.
NAME_RE='(^|/)(repro|reproducer|poc|exploit|trigger)[^/]*\.(c|h|txt|sh|py|prog|syz)$'
# Content sentinel -- assembled so this script does not contain the literal.
SENT='BRF-EMBARGO'; SENT="${SENT}-DO-NOT-PUSH"
ZERO=0000000000000000000000000000000000000000

violations=0
flag() { printf '  \xe2\x9c\x97 %-60s (%s)\n' "$1" "$2" >&2; violations=1; }

check_path() {
  local f="$1"
  printf '%s' "$f" | grep -Eq "$PROTECTED_RE" && flag "$f" "private/embargoed path"
  printf '%s' "$f" | grep -Eq "$NAME_RE"      && flag "$f" "reproducer/PoC filename"
}

case "$mode" in
  pre-commit)
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      check_path "$f"
      git show ":$f" 2>/dev/null | grep -qF "$SENT" && flag "$f" "embargo sentinel in content"
    done < <(git diff --cached --name-only --diff-filter=AM)
    ;;
  pre-push)
    remote="${2:-origin}"
    while read -r _lref lsha _rref rsha; do
      [ "$lsha" = "$ZERO" ] && continue   # branch deletion
      if [ "$rsha" = "$ZERO" ]; then
        commits=$(git rev-list "$lsha" --not --remotes="$remote")
      else
        commits=$(git rev-list "$rsha..$lsha")
      fi
      for c in $commits; do
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
The file(s) above are vulnerability triggers/reproducers or private working
memory that must NOT enter git history or reach a remote before the upstream
fix is merged.

If you are certain this is a false positive, bypass deliberately:
    git ${bypass} --no-verify
Pushing a pre-embargo reproducer is irreversible -- be sure.
==========================================================================
EOF
  exit 1
fi
exit 0
