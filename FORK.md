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

### Rules for performance changes (learned 2026-09-13)

Two mistake classes occurred in one day, and both are now guarded:

1. **Never cache anything that embeds per-request identity.** The permission
   cache (PR #19) is only safe because the four `users-*` permissions embed the
   calling user's id enum through the per-request `objects` schema and are
   therefore excluded from validator caching. Any future caching change to
   `backend/lib/access.js` must preserve that exclusion. The regression pin is
   `cached permission checks never leak one user's id into another's validation`
   in `backend/test/api.test.js` - it fails the suite if a cached validator is
   ever applied to a `users-*` permission, and it was verified to fail against
   a deliberately sabotaged guard before being trusted. Run it whenever touching
   access control, and keep the negative-verification habit: break the guard on
   purpose, prove the test turns red, restore, prove green.

2. **Verify the mechanism, not just the outcome, before writing it down.** The
   `mmap_size` exclusion (PR #20) was initially recorded with the wrong reason -
   "compiled out" - when the real mechanism was better-sqlite3's pragma-API
   whitelist silently rejecting it. Both the exclusion decision and its recorded
   justification were corrected in `85d9c244`. When a claim about a driver,
   dependency, or runtime enters the CHANGELOG, it must be backed by a direct
   probe of that exact build (e.g. `PRAGMA compile_options`), not inference
   from a symptom like an empty readback.

### Enforced guardrails (2026-09-13)

The two rule classes above are also machine-enforced so future sessions cannot
drift past them, even under pressure to "just make it work":

- `.github/CODE_GUIDELINES.md` is the always-loaded constraint summary for
  every coding session (VS Code reads it automatically): the nine security
  invariants, the change discipline, and the verification ladder. It points
  here and to the tests for rationale.
- `tests/security-invariants.mjs` runs in `lint-and-format` and fails the
  build on drift in five load-bearing properties: subprocess output never
  reaching API responses (app.js shape, error-object schema, CommandError
  visibility), the jwtdecode 401-for-rejected-session contract (comment-aware
  so a commented-out 401 cannot satisfy it), the no-store Cache-Control on
  the admin index and SPA fallback location blocks, the permission-cache
  identity exclusion (the `!referencesObjects` guard and the per-request
  objects rebuild), and the bounded-fetch timeout/byte-cap contracts.
- Every rule in the checker was **negative-verified before being trusted**:
  each guarded file was sabotaged with its real drift pattern, the checker
  had to catch it, and the tree was restored. A check that has never been
  seen to fail proves nothing - keep that discipline when adding rules.
- The behavioral layer is the regression pins in `backend/test/api.test.js`,
  notably `cached permission checks never leak one user's id into another's
  validation`, which was itself proven red against a sabotaged cache guard.
- When a new incident reveals a drift class worth guarding, add a rule to the
  checker AND a sabotage case to the negative-verification habit, never a
  rule alone. Never edit the checker to make a change pass; redesign the
  invariant with owner approval instead, and record it here.

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

Internal audit reports belong in ignored local storage, outside the published
`docs/` tree. Preserve the fork's `.gitignore` and `.dockerignore` exclusions and
intentional report deletions during upstream merges. Git ignore rules do not
prevent a merge from adding tracked files: review incoming documentation before
publishing a proposal. If upstream edits a report deleted by the fork, stop for
review rather than restoring it automatically. Keep security implementation,
regression tests, reporting policies, and scanner exception files maintained.
Local handoffs and private reports are not available in a fresh clone.

Release notes are user-facing and stay short: one line per change, no commit
hashes or file paths, with the full record kept in CHANGELOG. `.github/release-notes/TEMPLATE.md`
carries the skeleton and the rules; `release.yml` refuses a tag whose notes file
is missing or empty and appends the image-digest sections itself.

The 2026-09-08 tidy extracts the sync workflow into a tested script and the browser
deployment recovery into a dedicated module. Existing dashboard modules and
database migrations retain their paths.

The September 12 integration merges upstream `3d5ac185` through
[PR #16](https://github.com/mangyan1/NPMplus/pull/16), landed on `develop` as
`c891f43f`. Five conflicts were resolved: user routes, frontend manifest and
lockfile, and both CrowdSec nginx configurations. It preserves central Express
error handling, 401/403 semantics, server-side logout revocation, no-store HTML,
CrowdSec telemetry instrumentation, reviewed dependency versions, and nginx
basic-auth bcrypt cost 6. Public CommandError debug payloads were removed by the
security fixes in `8639e5a7`; do not reintroduce them during a later merge.

Upstream Argon2id login passwords and recovery codes are integrated. A conditional
legacy-hash update prevents a stale login from overwriting a password reset.
Token issuance waits out the revocation second rather than issuing future-dated
tokens. Preserve the migration, concurrent recovery-code, immediate-login, and
logout regression tests when updating shared authentication code.

Local validation passed: 118 backend tests, 10 frontend tests, production build,
schema, real-router/browser smoke, 8 Linux sync contracts, and 15 Linux recovery
tests. A disposable container check verified Argon2 password reset, session
revocation, and MFA clearing. PR checks, the candidate image vulnerability scan,
installer variants, and reboot resilience all passed before merging. The
[post-merge upstream sync](https://github.com/mangyan1/NPMplus/actions/runs/34697402798)
succeeded. This records a tested merge, not a guarantee for later upstream revisions.

The September 20 integration merges upstream `a1ac84c8` through
[PR #29](https://github.com/mangyan1/NPMplus/pull/29), landed on `develop` as the
merge commit `bfa66942` (parents `7e6aca60` + the reviewed merge `2dfec1a6`;
regular merge, ancestry preserved). Thirteen upstream commits, 18 conflicts.
It adopts upstream's per-row second-factor model, which is the one change that
could not be declined: see the resolution notes below. The fork's TOTP replay
protection, backup-code single-use, ACL ownership scoping, DB-backed token
challenges, and reviewed dependency versions are all preserved. Local validation:
163 backend tests, 15 frontend tests, `validate-schema`, both biome runs, the
production build, and `tests/security-invariants.mjs`. The three Linux-only python
contracts cannot run on the Windows rig (MSYS path mangling) and were confirmed
environmental by reproducing identical failures on a pristine `origin/develop`
worktree; all three are green on CI. Every PR check passed before merging, and the
post-merge `develop` push is green including `boot-resilience` and the caddy
build-and-scan job.

## Upstream merge resolution notes (September 13)

Upstream rewrote develop again (the previous integration `16116b76` was followed by
`58f8a1b9`, `968d7e07`, and `ec092c26`), which made the scheduled `upstream sync`
run fail closed on conflicts. That failure is the intended stop-for-review
behavior, not a CI regression. The prepared merge on `fix/upstream-sync-20260913`
resolves three files:

- `backend/app.js`: upstream now publishes `payload.error.output` from
  `CommandError` messages. That reintroduces the raw subprocess stdout/stderr leak
  (certbot command lines can carry credentials and paths) that `8639e5a7`
  removed, so the fork's generic-message handler is kept. The auto-merged
  `error-object.json` `output` property was reverted for the same reason: the
  schema must describe what this fork actually returns. The frontend modal
  changes are kept because `err.payload?.error?.output` is simply never set; the
  translated `<T id={err.message}>` fallback renders instead.
- `backend/internal/user.js`: upstream's avatar rework (id-keyed gravatar cache,
  magic-byte image detection, stale-extension cleanup, post-insert avatar patch)
  is adopted, merged with the fork's hardening: the bounded 5s fetch timeout and
  1 MiB bounded body read remain, and `backfillGravatarAvatar` keeps backfilling
  empty avatars on login (now writing id-keyed files). The gravatar contract
  tests assert the id-keyed file names.
- `backend/routes/users.js`: upstream's strict setup whitelist (only `name`,
  `nickname`, `email`, `auth`, forced `roles: ["admin"]`) replaces the fork's
  field-defaulting block, while the fork's setup-mode race guard
  (`setupCreationInProgress`), one-time setup-token verification, token removal
  on completion, and `finally` release are preserved. The tightened
  `post.json` `auth` object schema (password type/secret required when present)
  is accepted; the admin UserModal sends no `auth` on create and the setup
  wizard sends exactly `name`, `nickname`, `email`, `auth`.

Auto-merged without conflicts: `backend/setup.js` now seeds the initial admin via
`internalUser.create` with internal access (the audit entry records user id 1),
`backend/schema/paths/users/post.json`, the seven frontend certbot-error modals,
and `rootfs/usr/local/bin/envs.sh` (the upstream Unraid app-template refusal and
the `UID`/`GID`/`$UID`-env root checks; the fork's compose.yaml sets neither, so
the standard deployment is unaffected).

The installer smoke workflow points its self-check at the file under test via a
`file://` SELF_URL; the production stale-script guard remains enabled. Channel
selection and password-hash rollback compatibility are documented in the
[operations guide](docs/setup-npmplus.md#september-12-develop-upgrade).

## Upstream merge resolution notes (September 20)

The scheduled `upstream sync` run was red because upstream force-pushed `develop`
again after the previous integration (`82a09947`); that is the intended
stop-for-review behavior, not a CI regression. Merging the current upstream tip
through [PR #29](https://github.com/mangyan1/NPMplus/pull/29) restores it. The
reviewed merge on `fix/upstream-sync-20260920` resolves 18 files; the decisions
that matter:

- **Second factors moved to their own rows.** Upstream `7efc56c0` gives each
  factor its own `auth` row under a `type` column (`password`, `totp`,
  `totp_pending`, `backup_code`), and its migration
  `20260919230355_auth_factor_rows.js` clears `meta` to `{}` on every password
  row. The fork's factors lived in `auth.meta`, so keeping our side was not a
  different-but-working option: upstream's migration would have wiped the fields
  those functions read, silently turning 2FA off and locking out the users who
  rely on it. Adopted, with both fork protections re-expressed on the row model:
  - TOTP replay stays atomic. `verifyCode` claims the matched step with an
    id-scoped conditional patch
    (`WHERE id = ? AND (last_used_step IS NULL OR last_used_step < ?)`), so
    concurrent logins cannot reuse a code, and a run whose enrollment row was
    replaced mid-verification has nothing left to claim. `enable` stamps the
    step the enrollment code came from when it promotes `totp_pending` to
    `totp`, and that promotion is itself conditional on the row still being
    pending.
  - Backup codes stay single-use through the row-existence-guarded delete
    (`findById(code.id).delete() === 1`), equivalent to the fork's CAS under
    concurrency.
  - `models/auth.js` drops the now-unused `getPasswordAuthSnapshot` and the
    `metaCast` static (the DB-cast optimistic lock is obsolete under rows) and
    adds `getTotpEnrollment`.
- **`validateAccessLists` takes upstream's argument order.** The body remains the
  fork's, which is stricter than upstream's visibility check: non-admins are
  scoped to their own ACLs via `canAdmin()` (try/catch, as in
  `lib/nginx-privilege.js`), and a missing `access` throws so a future caller
  cannot skip the scoping. This supersedes the
  `validateAccessLists(proxyHost, access)` order recorded for rc.8 — same
  semantics, upstream's order, both call sites in `proxy-host.js` updated.
- **Token challenges stay DB-backed.** Upstream's `a59e3db1` adds an in-memory
  `consumedChallenges` map whose own message concedes that restarts break it.
  The fork removed that map deliberately, so `token.js` is kept and the map is
  not reintroduced.
- **Dependency versions stay fork-side.** `backend/package.json`,
  `frontend/package.json` and both lockfiles are kept: upstream's bumps
  (`6887f082`, `20b56ee8`) are younger than the 7-day `minimumReleaseAge`
  window. Both workspaces still install under `--frozen-lockfile`, and the
  renovate cron ages the bumps in.
- **`access-list.js`** hashing takes upstream's async `bcrypt.hash` at the
  fork's cost 6.

Adopted from upstream without argument: the alpine `3.24.2` bump (`7dac39b6`) in
both Dockerfiles — nginx `release-1.31.6` and aws-lc `v5.9.0` were already the
fork's pins, so nothing was dropped — the uppercase-hex IPv6 binding acceptance
in `envs.sh`, the stricter certificate domain pattern in
`certificate-object.json`, `ubuntu-26.04-arm` in `docker-develop.yml`, and the
`| default: env.AUTH_REQUEST_*_UPSTREAM` fallbacks in `proxy_host.conf`, which
compose with the fork's `_upstream_resolved` handling. Four test files were
adapted to the row model (`mfa`, `totp-replay`, `sqlite-upgrade`). The ACL
ownership test was verified to still bite: with the scoping disabled, the hijack
`PUT` returns 200 instead of 400.
