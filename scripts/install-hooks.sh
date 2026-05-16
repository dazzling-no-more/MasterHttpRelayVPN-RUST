#!/usr/bin/env bash
# One-shot installer: points git at the version-controlled hook directory.
# Run once per clone. No copying — `core.hooksPath` makes git read hooks
# directly from scripts/git-hooks/, so updates to the hook show up the
# next time someone pulls.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

git config core.hooksPath scripts/git-hooks
chmod +x scripts/git-hooks/pre-commit 2>/dev/null || true

echo "git hooks installed (core.hooksPath = scripts/git-hooks)"
