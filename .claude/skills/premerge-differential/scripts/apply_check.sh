#!/bin/bash
# Apply every candidate series STANDALONE on the base, then break each failure
# down per patch. Read-only for the repo except a throwaway detached worktree.
#
# Usage: apply_check.sh <kernel-repo> <base-ref> <intake-dir>
#   <intake-dir> is pw_intake.py's OUT_DIR (needs candidates.tsv + mbox/).
# Writes <intake-dir>/apply_check.tsv and <intake-dir>/fail_analysis.txt.
#
# Result per series: CLEAN (plain git am) | 3WAY (needs -3: a human must review
# the placement before it is used) | FAIL@<patch>. Per failing patch:
# applies | ALREADY-IN-BASE (reverse-applies) | 3way-only | CONFLICT.
set -u
REPO=$1 BASE=$2 IN=$3
WT=$(mktemp -d)/apply_wt
git -C "$REPO" worktree add -q --detach "$WT" "$BASE" || exit 1
trap 'git -C "$REPO" worktree remove --force "$WT"' EXIT
cd "$WT" || exit 1
git config user.email apply-check@localhost; git config user.name apply-check
B=$(git rev-parse HEAD)

: > "$IN/apply_check.tsv"
tail -n +2 "$IN/candidates.tsv" | while IFS=$'\t' read -r id ver n date author title msgid lore; do
  git reset -q --hard "$B"; git am --abort >/dev/null 2>&1
  m=$IN/mbox/$id.mbox
  if git am -q "$m" >/dev/null 2>&1; then r=CLEAN
  else
    git am --abort
    if git am -q -3 "$m" >/dev/null 2>&1; then r=3WAY
    else r="FAIL@$(git am --show-current-patch 2>/dev/null | grep -m1 '^Subject' | cut -c10-70)"; git am --abort; fi
  fi
  areas=$(git diff --name-only "$B" HEAD | awk -F/ '{print $1"/"$2}' | sort -u | tr '\n' ' ')
  stat=$(git diff --shortstat "$B" HEAD)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$ver" "$r" "$stat" "$areas" "$title" "$lore" >> "$IN/apply_check.tsv"
done

: > "$IN/fail_analysis.txt"
awk -F'\t' '$3 !~ /^(CLEAN|3WAY)$/ {print $1}' "$IN/apply_check.tsv" | while read -r id; do
  git reset -q --hard "$B"
  d=$(mktemp -d); git mailsplit -o"$d" "$IN/mbox/$id.mbox" >/dev/null
  echo "== $id $(awk -F'\t' -v i="$id" '$1==i{print $6"  "$7}' "$IN/apply_check.tsv")" >> "$IN/fail_analysis.txt"
  for p in "$d"/*; do
    subj=$(grep -m1 '^Subject:' "$p" | sed -E 's/^Subject: *(\[[^]]*\] *)*//' | cut -c1-60)
    grep -q '^diff --git' "$p" || { echo "   no-diff      $subj" >> "$IN/fail_analysis.txt"; continue; }
    if git am -q "$p" >/dev/null 2>&1; then st=applies
    else git am --abort
      if git apply --check -R "$p" 2>/dev/null; then st=ALREADY-IN-BASE
      elif git am -q -3 "$p" >/dev/null 2>&1; then st=3way-only
      else git am --abort; st=CONFLICT; fi
    fi
    echo "   $st  $subj" >> "$IN/fail_analysis.txt"
  done
  rm -rf "$d"
done
echo "wrote $IN/apply_check.tsv and $IN/fail_analysis.txt"
