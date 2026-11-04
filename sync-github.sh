#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

BRANCH="$(git branch --show-current)"

if [ "$BRANCH" != "main" ]; then
  echo "ERROR: Branch bukan main."
  exit 1
fi

git add -A

if git diff --cached --name-only | grep -E '(^|/)\.env($|\.)|^data/|(^|/)[^/]*backup-' ; then
  echo "ERROR: File rahasia atau backup terdeteksi. Push dibatalkan."
  git reset
  exit 1
fi

if ! git diff --cached --quiet; then
  git commit -m "Update dashboard from VPS"
else
  echo "Tidak ada commit baru. Mengirim commit yang tertunda..."
fi

git push origin main

echo "BERHASIL: GitHub sudah menerima perubahan VPS."
