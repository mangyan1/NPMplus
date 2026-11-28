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

label='upstream-sync'
# One open tracking issue holds the blocked-merge state. Its body ends with
# `upstream-sync:<signature>` so a later run can tell "still the same conflict"
# from "the conflict changed" without keeping state anywhere else.
run_url="${GITHUB_SERVER_URL:-https://github.com}/${GH_REPO}/actions/runs/${GITHUB_RUN_ID:-unknown}"

# --search is used instead of --label because the label may not exist yet and gh
# rejects an unknown label filter, while the search simply returns nothing.
tracking_issue_number() {
  gh issue list --repo "$GH_REPO" --search "label:$label state:open" --json number \
    --jq '.[-1].number // "none"'
}

tracking_issue_signature() {
  gh issue list --repo "$GH_REPO" --search "label:$label state:open" --json body \
    --jq '[.[] | .body // ""] | join("\n")' |
    sed -n 's/^upstream-sync:\([0-9a-f]\{16\}\)$/\1/p' | head -n 1
}

# A conflict is expected, transitional state: it repeats on every run until a
# human lands a reconciliation merge. Reporting is edge-triggered so one known
# conflict cannot notify once per day.
ensure_label() {
  if [[ "$(gh label list --repo "$GH_REPO" --limit 500 --json name \
    --jq "map(.name) | index(\"$label\") != null")" == true ]]; then
    return 0
  fi
  gh label create "$label" --repo "$GH_REPO" --color B60205 \
    --description 'Upstream develop cannot be merged here without a human reconciliation merge'
}

# Bookkeeping must never mask the sync result, so every caller wraps this in a
# conditional and the summary records a failure to close.
resolve_tracking_issue() {
  local number
  number=$(tracking_issue_number) || return 1
  if [[ "$number" == none ]]; then
    return 0
  fi
  gh issue close "$number" --repo "$GH_REPO" --reason completed \
    --comment "Upstream develop is merged into this fork again (upstream $1). The upstream sync workflow closes the blocked-merge tracking issue." || return 1
  printf 'Tracking issue #%s was closed: upstream is mergeable again.\n' "$number" >>"$GITHUB_STEP_SUMMARY"
}

if git merge-base --is-ancestor upstream/develop origin/develop; then
  echo 'The fork already contains this upstream revision.' >>"$GITHUB_STEP_SUMMARY"
  if ! resolve_tracking_issue "$upstream"; then
    echo 'A blocked-merge tracking issue is still open; close it after checking the merge.' >>"$GITHUB_STEP_SUMMARY"
  fi
  exit 0
fi

# Record the expected remote tip before preparing the merge. Concurrent updates
# to this automation branch must cause the push to fail, not be overwritten.
expected=$(git ls-remote --heads origin "refs/heads/$branch" | cut -f1)
git switch -C "$branch" origin/develop
if ! git merge --no-ff upstream/develop -m 'merge upstream develop'; then
  mapfile -t files < <(git diff --name-only --diff-filter=U | sed '/^$/d' | sort)
  if [[ ${#files[@]} -eq 0 ]]; then
    echo 'Git could not prepare the merge. Inspect the job log; no proposal was published.' >>"$GITHUB_STEP_SUMMARY"
    git merge --abort || true
    exit 1
  fi
  signature=$(printf '%s\n' "$upstream" "${files[@]}" | sha256sum | cut -c1-16)
  {
    echo 'Merge conflicts require review; no branch or pull request was published.'
    printf '\nBlocked upstream revision: %s\n\nSignature: %s\n\n' "$upstream" "$signature"
    echo '```text'
    printf '%s\n' "${files[@]}"
    echo '```'
    echo 'Follow FORK.md. Preserve required fork behavior; do not discard fork commits or rewrite develop.'
  } >>"$GITHUB_STEP_SUMMARY"

  ensure_label
  number=$(tracking_issue_number)
  known=$(tracking_issue_signature)
  if [[ "${GITHUB_EVENT_NAME:-}" == schedule && -n "$known" && "$known" == "$signature" ]]; then
    {
      printf 'Unchanged since issue #%s: upstream %s still conflicts in %s file(s). No new report was published and no notification was sent.\n' \
        "$number" "$upstream" "${#files[@]}"
      printf 'upstream-sync:%s\n' "$signature"
    } >>"$GITHUB_STEP_SUMMARY"
    printf '::notice::upstream sync is still blocked at %s (%s file(s), already reported in issue #%s)\n' \
      "${upstream:0:12}" "${#files[@]}" "$number"
    git merge --abort || true
    exit 0
  fi

  body=$(mktemp)
  trap 'rm -f -- "$body"' EXIT
  {
    echo 'Upstream `develop` cannot be merged into this fork without a human reconciliation merge, so this run published no proposal branch and no pull request.'
    echo
    printf -- '- Base: `%s`\n- Upstream: `%s`\n- Conflicted files: %s\n' "$base" "$upstream" "${#files[@]}"
    echo
    echo '```text'
    printf '%s\n' "${files[@]}"
    echo '```'
    echo
    echo 'Resolve these conflicts in one merge commit as described in FORK.md (Upstream sync behavior and the reconciliation notes), keeping the fork installer, security integrations, and reporting behavior. Never squash or rebase the reconciliation merge commit, and never rewrite `develop` or a release tag.'
    echo
    printf 'Latest red run: %s\n' "$run_url"
    echo
    printf 'upstream-sync:%s\n' "$signature"
  } >"$body"

  if [[ "$number" == none ]]; then
    gh issue create --repo "$GH_REPO" --label "$label" \
      --title "upstream sync blocked at ${upstream:0:12}: ${#files[@]} file(s) conflict" --body-file "$body"
    where="opened a tracking issue"
  else
    gh issue edit "$number" --repo "$GH_REPO" --body-file "$body"
    printf 'Tracking issue #%s now describes the current conflict state.\n' "$number" >>"$GITHUB_STEP_SUMMARY"
    where="tracking issue #$number was updated"
  fi
  printf '::error title=Upstream sync blocked::%s file(s) conflict with upstream %s; %s\n' \
    "${#files[@]}" "${upstream:0:12}" "$where"
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
if ! resolve_tracking_issue "$upstream"; then
  echo 'A blocked-merge tracking issue is still open; close it after checking the merge.' >>"$GITHUB_STEP_SUMMARY"
fi
echo 'Proposal ready for review. Approve pending workflow runs and check FORK.md before merging.' >>"$GITHUB_STEP_SUMMARY"
