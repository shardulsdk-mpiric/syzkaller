#!/usr/bin/env bash
# Activate the BRF embargo guard for this clone. Run once after cloning:
#   ./githooks/install.sh
# It points git at the tracked githooks/ directory and makes the hooks
# executable. Idempotent. To disable: `git config --unset core.hooksPath`.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
chmod +x githooks/embargo_guard.sh githooks/pre-commit githooks/pre-push
git config core.hooksPath githooks
echo "Embargo guard active: core.hooksPath -> githooks/"
echo "  pre-commit + pre-push will block embargoed reproducers/triggers."
echo "  Bypass a confirmed false positive with: git commit/push --no-verify"
