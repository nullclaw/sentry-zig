#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARD_RESET=false

if [[ "${1:-}" == "--hard" ]]; then
  HARD_RESET=true
fi

repos=(
  "https://github.com/getsentry/sentry-native.git"
)

for repo in "${repos[@]}"; do
  name="$(basename "${repo}" .git)"
  target="${ROOT_DIR}/${name}"

  if [[ -d "${target}/.git" ]]; then
    echo "Updating ${name}..."
    git -C "${target}" fetch --depth 1 origin
    if [[ "${HARD_RESET}" == "true" ]]; then
      git -C "${target}" reset --hard origin/HEAD
    elif [[ -n "$(git -C "${target}" status --porcelain)" ]]; then
      echo "Skipping ${name} (local changes present; use --hard to discard)."
    else
      git -C "${target}" reset --hard origin/HEAD
    fi
  else
    echo "Cloning ${name}..."
    git clone --depth 1 "${repo}" "${target}"
  fi
done

echo "Reference sources are ready under ${ROOT_DIR}"
