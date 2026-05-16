#!/usr/bin/env bash
# One-shot installer:
#   1. Points git at the version-controlled hook directory via core.hooksPath.
#   2. Downloads a pinned ktlint to .git/hooks-cache/ for the Kotlin format
#      check. Cached under .git/ so it's per-clone and never committed.
# Run once per clone. Updates to the hook itself show up automatically on
# `git pull`; bumping ktlint requires re-running this script.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

git config core.hooksPath scripts/git-hooks
chmod +x scripts/git-hooks/pre-commit 2>/dev/null || true

# ---- ktlint cache -------------------------------------------------------
ktlint_version="1.8.0"
ktlint_sha256="a3fd620207d5c40da6ca789b95e7f823c54e854b7fade7f613e91096a3706d75"
ktlint_url="https://github.com/pinterest/ktlint/releases/download/${ktlint_version}/ktlint"
cache_dir=".git/hooks-cache"
ktlint_jar="${cache_dir}/ktlint-${ktlint_version}.jar"

mkdir -p "$cache_dir"

# Symlink-or-pointer to "current" so the hook doesn't have to know the
# version. Plain file on Windows (Git Bash symlinks need admin).
ktlint_current="${cache_dir}/ktlint.jar"

if [ -f "$ktlint_jar" ]; then
  echo "ktlint ${ktlint_version} already cached at $ktlint_jar"
else
  if ! command -v curl >/dev/null 2>&1; then
    echo "error: curl not found - install curl or download ktlint manually to $ktlint_jar" >&2
    exit 1
  fi
  echo "downloading ktlint ${ktlint_version}..."
  curl -fsSL "$ktlint_url" -o "${ktlint_jar}.tmp"

  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "${ktlint_jar}.tmp" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "${ktlint_jar}.tmp" | awk '{print $1}')
  else
    echo "error: no sha256sum/shasum available - cannot verify ktlint integrity" >&2
    rm -f "${ktlint_jar}.tmp"
    exit 1
  fi

  if [ "$actual" != "$ktlint_sha256" ]; then
    echo "error: ktlint SHA-256 mismatch" >&2
    echo "  expected: $ktlint_sha256" >&2
    echo "  actual:   $actual" >&2
    rm -f "${ktlint_jar}.tmp"
    exit 1
  fi
  mv "${ktlint_jar}.tmp" "$ktlint_jar"
  echo "ktlint ${ktlint_version} cached at $ktlint_jar"
fi

cp -f "$ktlint_jar" "$ktlint_current"

echo "git hooks installed (core.hooksPath = scripts/git-hooks)"
