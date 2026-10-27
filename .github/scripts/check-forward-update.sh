#!/usr/bin/env bash
set -euo pipefail

# Exit 1 only for an already included version; comparison failures must fail CI.
repository="$1"
current_sha="$2"
candidate_sha="$3"
if ! comparison="$(gh api "repos/$repository/compare/$current_sha...$candidate_sha" --jq '.status')"; then
  echo "Unable to verify dependency ancestry" >&2
  exit 2
fi
case "$comparison" in
  ahead) exit 0 ;;
  identical|behind)
    echo "Candidate is already included in the current dependency pin"
    exit 1
    ;;
  *)
    echo "Dependency comparison is not a forward update: $comparison" >&2
    exit 2
    ;;
esac
