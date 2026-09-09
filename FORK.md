# Maintaining the NPMplus security fork

This fork follows `ZoeyVid/NPMplus` while maintaining the installer, CrowdSec and
Anubis reporting, recovery tooling, and documented security corrections. Upstream
updates enter through reviewed merge proposals into `mangyan1/NPMplus:develop`.
The installed server then updates from this fork's tested image and installer.

Small, isolated additions reduce merge conflicts. They cannot guarantee that
future upstream changes will preserve behavior, even when Git merges cleanly.
Keep existing paths where they already isolate a feature; moving every file into
a new directory would add merge work without improving the boundary.

## Where fork behavior belongs

| Area | Fork-owned implementation | Shared integration points to review |
| --- | --- | --- |
| Installation and recovery | `setup-npmplus.sh`, doctors, `tests/installer-recovery.py` | Compose mounts, rootfs startup, health checks, image channels |
| Security dashboard | `frontend/src/pages/Crowdsec/`, CrowdSec API/hooks and manual-ban modal | Router, admin menu/permissions, translations, proxy-host controls |
| Security API and retained observations | CrowdSec routes/internal helpers, Anubis reporting, security telemetry and their tests | `backend/routes/main.js`, startup in `backend/index.js`, database migrations |
| Browser deployment recovery | `frontend/src/fork/deployment-recovery.ts`, `ErrorBoundary.tsx` | Small startup call in `main.tsx`, route boundary in `Router.tsx`, nginx no-store policy |
| nginx enforcement observations | `npmplus_telemetry.lua`, private telemetry listener, bouncer instrumentation script | Dockerfile hook, proxy template host ID, rootfs configuration |
| Fork publishing and maintenance | Fork release/security/smoke workflows, `.github/scripts/upstream-sync.sh`, this guide | Upstream dependency changes, image builds, final-image scans |
| Security corrections in shared code | Auth, OIDC/MFA, validation, nginx privilege handling, certificate compatibility tests | Review each overlapping upstream change against the relevant regression test |

Prefer one small import or startup call in a shared entry point over embedding a
new subsystem there. Add implementation beside the existing feature modules.
Avoid unrelated formatting, bulk renaming, dependency churn, or moving historical
migrations. Never remove a required security correction just to shrink the diff.

Certificate behavior has an additional owner restriction: do not restructure
`backend/internal/certificate.js`. Preserve DNS plugin installation and deliberately
update `backend/test/certificate-dns.test.js` before any approved behavior change.

## Upstream sync behavior

The daily/manual `upstream sync` workflow runs only in `mangyan1/NPMplus`. Its
script refreshes ZoeyVid's `develop` tracking ref and prepares a merge on
`automation/upstream-sync` from the current `origin/develop`.

- Every `gh` API command names the fork explicitly. GitHub CLI can otherwise
  [default to a fork's parent](https://cli.github.com/manual/gh_repo_clone).
- If upstream is already included, nothing is published.
- A clean merge refreshes the disposable proposal branch and opens a PR if one
  does not already exist. Only that branch may be replaced, with an explicit
  expected-tip lease that rejects concurrent updates.
- A conflict stops the run and lists the files in its summary. The existing
  proposal, `develop`, and release tags remain untouched. Other merge/GitHub
  failures are reported as failures, rather than being mistaken for no changes.
- The workflow does not auto-merge, deploy, create a release, or post issues to
  either repository. Check the job summary when a scheduled run is red.

GitHub may put PR checks created with `GITHUB_TOKEN` into an approval-required
state. Select **Approve workflows to run** on the PR and wait for required checks.
See [GitHub's token event rules](https://docs.github.com/en/actions/concepts/security/github_token).
If PR creation is denied, verify the target repository and its Actions setting
allowing Actions to create pull requests; do not broaden permissions upstream.

The script is intended for an Actions checkout. Use the local procedure below
when reviewing a merge manually. Its regression tests use local bare Git remotes
and a fake GitHub CLI; no real branch or PR is created by the tests.

## Reviewing an upstream update

From a clean checkout, fetch and inspect before changing the working branch:

```bash
git fetch origin develop
git fetch upstream develop
git log --oneline origin/develop..upstream/develop
git merge-tree --write-tree --name-only origin/develop upstream/develop
```

`merge-tree` creates Git objects without changing the index or working tree. A
zero exit code establishes only that the text merge succeeds. For an actual
review, create a separate branch from `origin/develop`, merge upstream there,
and resolve overlaps file by file. Never reset `develop` to upstream, rebase away
published fork commits, or blindly select one side of every conflict.

When upstream replaces one of our fixes, compare behavior and regression tests.
Keep the upstream implementation if it covers the same requirements, then remove
only the redundant fork implementation in a normal reviewable commit. Preserve
attribution and upstream history with merge commits.

Before merging the proposal:

1. Review the shared integration points above, dependency/lockfile changes, and
   any upstream rewrite. Confirm admin authorization, 401/403 semantics, DNS-01
   support, CrowdSec/AppSec/Anubis enforcement, and no-store HTML behavior survive.
2. Run `lint-and-format`: both application linters/tests, schema validation,
   installer recovery tests, sync contracts, frontend build, translation sorting,
   and the clean-diff gate. Run `python3 tests/upstream-sync.py` directly on Linux
   when changing sync behavior; it needs Bash and Git.
3. Exercise affected browser/API smoke flows. Deployment changes also need the
   installer variants, Debian restore, boot-resilience, and relevant image scans.
   Wait for required checks; an absence of checks is not a pass.
4. Merge the reviewed proposal into this fork and let its image build finish.
   Update installed servers with this fork's safe updater. A direct switch to
   ZoeyVid's image is a separate migration, not this sync process.

## Documentation and current verification

Update this tracked guide when an integration boundary or sync rule changes.
Record user-visible behavior in CHANGELOG and the relevant `docs/` guide. The
local `AGENTS.md` handoff is intentionally ignored and must not be force-added;
durable maintenance rules therefore also live here.

The 2026-09-08 tidy extracts the sync workflow into a tested script and the browser
deployment recovery into a dedicated module. Existing dashboard modules and
database migrations retain their paths. The latest upstream revision inspected
was `5507ba49`; its merge simulation against `dbb85f13` had no text conflicts.
That upstream merge was not applied or runtime-tested as part of the tidy.

Local validation passed: eight sync regression tests, ShellCheck, changed-workflow
actionlint, frontend Biome in CI mode, TypeScript/eight frontend tests, production
build, 68 browser checks, and changed-file spellcheck. Desktop and 320px dashboard
screenshots were inspected. GitHub PR creation by the revised workflow still needs
verification after the changes are published.
