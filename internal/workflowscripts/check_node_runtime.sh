#!/usr/bin/env bash
# Fail when a workflow or local action uses an unsupported Node runtime.
set -euo pipefail

unsupported_runtime() { case "$1" in node12|node16|node20) return 0;; esac; return 1; }
hit=0
declare -A files_for=()

files="$(
  if [ -d .github/workflows ]; then
    find .github/workflows -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) || exit
  fi
  if [ -d .github/actions ]; then
    find .github/actions -type f \( -name action.yml -o -name action.yaml \) || exit
  fi
)"

while IFS= read -r file; do
  [[ -f "$file" ]] || continue
  uses=$(yq -r '.. | select(tag == "!!map") | .uses | select(. != null)' "$file")
  while IFS= read -r action; do
    action="${action%$'\r'}"
    [[ -z "$action" || "$action" == ./* || "$action" == docker://* || "$action" != *@* ]] && continue
    [[ "${action%@*}" == */.github/workflows/* ]] && continue
    files_for["$action"]+="${file#./} "
  done <<< "$uses"
  if [[ "$file" == .github/actions/* ]]; then
    using=$(yq -r '.runs.using // ""' "$file")
    if unsupported_runtime "$using"; then
      echo "::error file=$file::Action $file uses unsupported Node runtime $using"
      hit=1
    fi
  fi
done <<< "$files"

for action in "${!files_for[@]}"; do
  slug="${action%@*}"
  ref="${action##*@}"
  owner="${slug%%/*}"
  rest="${slug#*/}"
  if [[ "$owner" == "$slug" || -z "$owner" || -z "$rest" ]]; then
    echo "::warning::Unable to parse $action used in ${files_for[$action]% }"
    continue
  fi
  repo="${rest%%/*}"
  path=""
  [[ "$rest" == */* ]] && path="${rest#*/}"
  manifest=""
  for name in action.yml action.yaml; do
    if manifest=$(gh api "repos/$owner/$repo/contents/${path:+$path/}$name?ref=$ref" -H 'Accept: application/vnd.github.raw' 2>/dev/null); then
      break
    fi
    manifest=""
  done
  if [[ -z "$manifest" ]]; then
    echo "::warning::Unable to resolve $action used in ${files_for[$action]% }"
    continue
  fi
  using=$(printf '%s\n' "$manifest" | yq -r '.runs.using // ""')
  if unsupported_runtime "$using"; then
    for file in ${files_for[$action]}; do
      echo "::error file=$file::Action $action uses unsupported Node runtime $using"
    done
    hit=1
  fi
done
exit "$hit"
