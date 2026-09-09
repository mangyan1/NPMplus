#!/bin/bash
# Run only in the disposable upstream-sync Actions checkout. See FORK.md.
set -euo pipefail

: "${GH_REPO:?the fork repository must be explicit}"
: "${GITHUB_STEP_SUMMARY:?the Actions summary path must be set}"
[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo 'run this through the upstream sync workflow' >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo 'refusing a dirty checkout' >&2; exit 1; }

branch=automation/upstream-sync
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
if git remote get-url upstream >/dev/null 2>&1; then
  git remote set-url upstream https://github.com/ZoeyVid/NPMplus.git
else
  git remote add upstream https://github.com/ZoeyVid/NPMplus.git
fi
git fetch --no-tags origin develop
# Upstream may rewrite develop. This refreshes a tracking ref, never our branch.
git fetch --no-tags upstream +refs/heads/develop:refs/remotes/upstream/develop
base=$(git rev-parse origin/develop)
upstream=$(git rev-parse upstream/develop)
{
  echo '## Upstream merge proposal'
  printf 'Fork: %s\n\nBase: %s\n\nUpstream: %s\n\n' "$GH_REPO" "$base" "$upstream"
} >>"$GITHUB_STEP_SUMMARY"

if git merge-base --is-ancestor upstream/develop origin/develop; then
  echo 'The fork already contains this upstream revision.' >>"$GITHUB_STEP_SUMMARY"
  exit 0
fi

# Record the expected remote tip before preparing the merge. Concurrent updates
# to this automation branch must cause the push to fail, not be overwritten.
expected=$(git ls-remote --heads origin "refs/heads/$branch" | cut -f1)
git switch -C "$branch" origin/develop
if ! git merge --no-ff upstream/develop -m 'merge upstream develop'; then
  conflicts=$(git diff --name-only --diff-filter=U)
  if [[ -n "$conflicts" ]]; then
    {
      echo 'Merge conflicts require review; no branch or pull request was published.'
      echo '```text'
      printf '%s\n' "$conflicts"
      echo '```'
      echo 'Follow FORK.md. Preserve required fork behavior; do not discard fork commits or rewrite develop.'
    } >>"$GITHUB_STEP_SUMMARY"
  else
    echo 'Git could not prepare the merge. Inspect the job log; no proposal was published.' >>"$GITHUB_STEP_SUMMARY"
  fi
  git merge --abort || true
  exit 1
fi

# gh defaults to the parent repository in many fork checkouts. Every API command
# must target this fork explicitly, including the existing-PR lookup.
count=$(gh pr list --repo "$GH_REPO" --head "$branch" --base develop --state open --json number --jq length)
git push --force-with-lease="refs/heads/$branch:$expected" origin "HEAD:refs/heads/$branch"
if [[ "$count" == 0 ]]; then
  body=$(mktemp)
  trap 'rm -f -- "$body"' EXIT
  cat >"$body" <<'BODY'
Merge ZoeyVid/NPMplus develop into this fork while preserving its installer, security integrations, and reporting behavior.

Review the integration points and validation requirements in FORK.md. A clean Git merge does not establish runtime compatibility. Keep all required checks green before merging; this proposal does not update develop or publish a release.

GitHub may require a maintainer to select **Approve workflows to run** for this automation-created pull request. Do not merge while checks are missing or awaiting approval.
BODY
  if ! gh pr create --repo "$GH_REPO" --head "$branch" --base develop \
    --title 'merge upstream develop' --body-file "$body"; then
    printf 'Branch %s was pushed, but PR creation failed in %s. Inspect the error and repository Actions PR permissions; rerun after repair.\n' \
      "$branch" "$GH_REPO" >>"$GITHUB_STEP_SUMMARY"
    exit 1
  fi
fi
echo 'Proposal ready for review. Approve pending workflow runs and check FORK.md before merging.' >>"$GITHUB_STEP_SUMMARY"
