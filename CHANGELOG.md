# Changelog

All notable changes to the NPMplus Security Fork are documented here. The fork uses release identifiers based on the bundled NPMplus version followed by a fork-specific sequence.

## Unreleased

### Security

- Restricted Unix-socket and custom upstream destinations to administrators, including custom locations and stream upstream references. Built-in management sockets cannot be selected as proxy destinations.
- Added atomic TOTP timestep consumption and single-use login challenges. Enrollment codes cannot be reused for login; users must wait for the next authenticator code. Existing MFA enrollments migrate without resetting their secrets.
- Rejected access-list usernames containing htpasswd delimiters or control characters and excluded malformed legacy records during auth-file regeneration.

### Changed

- Reconciled upstream develop through `fce815df` (real merge commit, never squashed). Adopted: upstream's cert-visibility check — `create`/`update` on proxy, redirection, dead hosts and streams now reject a `certificate_id` the caller cannot see (the fork's IDOR fix already covered access lists; upstream's `daf5dff8` closes the certificate sibling), and backend mirrors of frontend validations on permission updates (`fce815df`: new non-admin users default to `hidden` on every resource, and a permission patch is rejected that leaves access lists hidden while proxy hosts are visible, or certificates hidden while any host type is visible). Dependency bumps taken only where they clear the 7-day pnpm `minimumReleaseAge` supply-chain gate (`@apidevtools/json-schema-ref-parser` 16.0.2, `mysql2` 3.24.4, `openid-client` 6.8.8, `react`/`react-dom` 19.3.0, `@tabler/core` 1.5.1, `vite` 8.3.0); the rest are rejected and stay on the reviewed versions until the renovate cron ages them in (`biome` 2.5.14, `multer` 2.4.0, `@tanstack/react-query` 5.103.1, `react-intl` 12.1.0, `react-router` 8.4.0, `markdown-to-jsx` 9.10.3 — all published inside the window). Upstream's `crowdsec.conf.example` change was a no-op for the fork: our file already shipped `APPSEC_FAILURE_ACTION=deny` and keeps `APPSEC_URL=` empty (upstream's default points at an endpoint that is not running — fork issue #3804). Fork invariants kept: the stricter `validateAccessLists(proxyHost, access)` admin-scoping (upstream's equivalent daf5dff8 ACL half was already ours, with `access` a required param), the fail-closed crowdsec posture, and the release-workflow replacement.
- Existing installs migrate off the fail-open bouncer posture automatically: the daily heal script's new step 5 rewrites a seeded `MODE=live` to `MODE=stream` and, when AppSec is wired, `APPSEC_FAILURE_ACTION=passthrough` to `deny`, then restarts npmplus so the change takes effect. Operators who want the old behavior opt out once with `touch /data/crowdsec/keep-fail-open`; `crowdsec-doctor.sh` step 8d points at the marker. The migration is exercised by `tests/heal-migration.py` in CI (six fixture cases: migrate-and-restart, marker opt-out, unwired AppSec keeps only the mode change, already-fail-closed confs untouched, a missing `FALLBACK_REMEDIATION` gets seeded, a deliberate `captcha` fallback is left alone).

- `APPSEC_FAILURE_ACTION=deny` alone is not fail-closed: the lua bouncer maps an AppSec outage to `FALLBACK_REMEDIATION`, and when the key is absent every remediation branch in `Allow()` falls through to allow — an AppSec outage then fails open with no error anywhere (proven in the docker attacker simulation by stopping the crowdsec container: requests still reached the origin, and adding `FALLBACK_REMEDIATION=ban` flipped them to the CrowdSec Ban page). The daily heal now seeds `FALLBACK_REMEDIATION=ban` into wired confs missing the key (present values stay untouched: `captcha` is a deliberate choice and the lua bouncer coerces invalid ones to `ban`), and doctor step 8d flags a `deny` action without a fallback as inert, notes the `captcha` caveat, and rejects invalid values.

- An AppSec outage under `APPSEC_FAILURE_ACTION=deny` served the CrowdSec Ban page with HTTP 200: upstream `lua-cs-bouncer`'s `AppSecCheck` returns its initial `status_code` placeholder on the failure path, so `ban.apply()` rendered the ban response as a 200 — status-code-based monitoring saw a healthy service while every request was denied. Upstream PR [lua-cs-bouncer#159](https://github.com/crowdsecurity/lua-cs-bouncer/pull/159) sets `ngx.HTTP_FORBIDDEN` in the deny branch; until the pin moves past it, the image build applies the same fix through the drift-guarded bouncer instrumentation script (both anchors fail the build loudly if the pinned source changes shape). Verified live: LAPI up, AppSec down, the ban page now answers 403.

- The Biome lint baseline is zero: the 101 warnings and 60 infos in the backend and 12 warnings and 2 infos in the frontend are gone. Real fixes: unused imports and unused route-handler parameters (`_next`-style renames), `.length > 0` checks, hoisted hot-path regex literals to module constants (backend Anubis/CrowdSec internals, the frontend scenario mapper), nested ternaries unwound into helpers or if/else, an Anubis probe's promise chain restructured out of a `.then` callback, shadowed test locals renamed, and best-effort `body.cancel()` moved before a nested-promise-free callback. Test fixtures carry documented `biome-ignore` comments (a fake secret-looking metadata value, a posix mode-mask `&`), and the backend biome config gains a `test/**` override (mirroring the `.smoke` one) that turns off the three Mocha-idiom rules (`noDoneCallback`, `useAwait`, `useTopLevelRegex`) where they only flag legitimate test style.

### Fixed

- Restored first-admin browser setup after the upstream removal of the client-supplied nickname field, retaining the one-time setup-token gate.
- Removed legacy Bootstrap dismiss handlers from the setup form and React-managed proxy editor, avoiding conflicting modal handling during browser setup and proxy saves.

- Fixed the CrowdSec dashboard and backend findings of the 2026-09-18 review. Each item was reproduced against a running instance before it was fixed; the one candidate that turned out to be deliberate — the manual-ban reason allowlist rejecting `/` while accepting no other path separator — was left alone as the test-pinned `REASONS_RE`. (1) The LAPI rewrites the registered bouncer's type and version from the request `User-Agent`, so every bouncer-key read now sends `LAPI_USER_AGENT` like the machine path does — without it the dashboard's own bouncer was relabelled `node`/`N/A` in `cscli bouncers list`, proven live against a real LAPI. (2) Every LAPI normalizer call goes through one `readContract` helper, so a contract mismatch answers a stable 502 `crowdsec.invalid-response` from all five readers instead of Express 5 forwarding the raw throw as a 500 "Internal Error" that the UI reported as a backend crash (`/insights`, `/anubis-report` and `/history/alerts` had no guard at all). (3) The insights counter maps are null-prototype: attacker-influenced values (a `Host` header, a request URI) are used as keys, so `constructor` or `__proto__` seeded a bogus row with a string count. (4) Signal ids are stable per type (`attack-spike`, `active-bans`) rather than `spike-<bucket>`/`bans-<count>`: the dashboard dedupes browser notifications on them, so an ongoing condition re-notified on every poll that saw a different number. The dedupe is now extracted as `notificationPlan` in `pages/Crowdsec/shared.ts` and also forgets a type once its signal clears, so a recurrence notifies again (four new frontend tests). (5) The refresh, dashboard and pager buttons test `isLoading` instead of `isFetching`: `Button` disables itself and drops `onClick` whenever `isLoading` is set, and `isFetching` is true for every background poll, so the 10-60s polls swallowed the operator's clicks. The history pager keeps `isFetching` in scan mode, where the next batch's cursor comes from the current response. (6) The ASN quick-filter chips go through the documented `asn:` field token — the free-text search matches `as_name` and `as_number` separately, so a chip labelled `AS64500` or `DIGITALOCEAN-ASN` matched nothing before. (7) The manual-ban modal warns when the ban is created but its audit record is not, matching the unban path. (8) Log lines a timer repeats are now reported once per outage. `debug()` is not level-gated and every one of these readers runs on a tick — the collectors every 60s, the dashboard routes on their poll interval — so a source that is merely absent filled the log with one identical line a minute: the three Anubis files an installation without Anubis never grows, the host firewall snapshot a stack without the firewall bouncer never produces, the nginx telemetry socket answering its deliberate "CrowdSec observation disabled" 503 where the bouncer is not installed, and the Anubis honeypot bridge (which degraded to a permanent "unavailable" badge with nothing in the logs at all). One `reportOutage`/`clearOutage` pair in `logger.js`, keyed per source, keeps the first line of each outage on an audible logger and re-arms on the next successful read, so a recovery followed by a new failure is reported again. The bridge's first version went to the muted express scope and was dead code — the test pinning the streak is what caught it. (9) The admin telemetry route answered `access-denied`, which is not a translation key, where every other route uses `access.denied`. All of it is verified end to end in docker against a real LAPI from a fresh install: 14/14 API checks (including the bouncer identity and a machine-token ban/unban round-trip) and 11/11 browser checks (including a refresh click surviving an in-flight refetch), with `vite build`, the backend suite (140 tests), the frontend suite (14 tests) and the security invariants green.

- The nginx observation no longer calls a deliberately switched-off source "unavailable". The Lua exporter's 503 body carries `"reason":"bouncer-not-installed"` beside its human message, the collector recognizes that one code and persists the disabled state in the same baseline row the API answers from, and `GET /api/crowdsec/telemetry` reports `nginx.status = "disabled"`: an installation with no CrowdSec bouncer enabled in nginx now says so instead of looking like a reader that cannot be reached, which is what the previous status word claimed for every failure, including this deliberate one. Nothing is observed and no interval is credited as covered, so the counters a bouncer accumulates while it is off are not replayed as traffic when it comes back — the disabled marker is explicitly not a counter baseline, and the interrupted interval stays partial history. Totals recorded before it was switched off remain visible, `unavailable` keeps its meaning for genuine read failures, and an unrefreshed marker ages into `stale` like any other row. The frontend's status union and the English label follow the new value, and both halves of the cross-language code are pinned by tests: the backend suite reads `npmplus_telemetry.lua` and fails if it stops emitting the code the reader matches. Verified live in the docker simulation against the real exporter, where the API now answers `disabled` for a container that loads no bouncer.

### Security

- Fixed the six findings of the 2026-09-16 CrowdSec integration audit. The image-seeded bouncer config no longer fails open: `crowdsec.conf.example` ships `MODE=stream` (bans survive LAPI outages, matching the installer path) and `APPSEC_FAILURE_ACTION=deny`, and `enable_crowdsec_appsec` upgrades an empty failure action to `deny` when it wires AppSec (an explicit operator `passthrough` stays untouched). `crowdsec-doctor.sh` gains a step 8d that flags `MODE=live` and AppSec `passthrough` on existing installs. Bouncer/machine key files are created race-free everywhere: `setup-npmplus.sh` routes every key/secret write through the existing `write_root_file` helper (mktemp is 0600 before the atomic rename), and the doctor and the daily heal script set `umask 077` so no creation window is world-readable. The heal cron now reopens the protected public gate only after the firewall bouncer is active with its INPUT/FORWARD rules restored (the doctor's step 8b standard, polled up to ten seconds) instead of after a bare key check. The LAPI certificate chain is validated through the http-level `lua_ssl_trusted_certificate` in `nginx.conf` (restating it inside the CrowdSec include is a duplicate directive that fails `nginx -t` the moment the include is enabled), the doctor's CAPI probe pipes the bouncer key through `curl --config -` instead of argv, the manual-ban failure audit mirrors the delete route's `err.public` gate, and the unused truthy-granting `hasCrowdsecAdminAccess` helper was deleted (backend suite green, 70 tests).

- Fixed the four findings of the 2026-09-16 security quality audit. A delegated manager can no longer attach another user's access list by guessing its integer id: `validateAccessLists` scopes attachable ACL ids to `owner_user_id` for non-admins, closing an IDOR that leaked foreign allow/deny CIDR rules and basic-auth usernames through `expand=access_lists` (admin attaches are unchanged). The permission model now fails closed on malformed inputs: `can()` rejects permission strings without a `type:level` shape, and `canUser()` rejects the anonymous-session sentinel `0` and non-integer/non-positive ids, so the unvalidated `DELETE /api/users/0/sessions` route answers 403 instead of reaching an unauthenticated 500. The nginx privilege guard snapshots `forward_port` for local-path hosts, so changing the fastcgi target port trips the admin-only guard. Both permission guards are pinned as rule 6 in `tests/security-invariants.mjs`, and the backend suite covers the IDOR round-trip, the sentinel 403, and the guard trip (132 tests).

## v2.15.1-mangyan1.rc.7 - 2026-09-16

Seventh public release candidate of the security-focused fork.

### Added

- Reconciled upstream develop through `2fcc605a` manually (the scheduled upstream-sync run had stopped on 42 conflicted files — its fail-closed behavior) and adopted upstream's typescript-to-javascript frontend migration: the react-query client, API modules, components, and pages are plain JavaScript now, and the frontend tsconfig, `tsc` build step, and typescript/`@types/*` devDependencies are gone. The fork-only `.ts`/`.tsx` sources (Anubis/CrowdSec/security UI, deployment recovery, error boundary) remain and run through Node 24 type stripping. Frontend tests run via `node --test test/*.test.ts`.

- Adopted upstream's simplified permission model (`isAdmin`, `canAdmin()`, `canUser(id)`, `can("type:manage")`, `get visibility()`) replacing the per-object permission walk; `access.js` drops to ~120 lines. The nginx privilege guard (raw config and local-path fields stay admin-only) and the CrowdSec route gate now wrap the synchronous `canAdmin()` call, and their tests were updated to the synchronous shape.

- Adopted upstream's nginx control API: config reload now patches `http://localhost/1/control/config` over the `/run/nginx-control.sock` unix socket via the undici client instead of running `nginx -s reload`; the API tests stub the reload since the socket does not exist in the test environment. `undici` 8.10.2 enters the backend manifest (verified 11 days published at merge time, inside the `minimumReleaseAge` window).

- `nickname` is now server-managed: absent from all API schemas and responses, with the `nickname_default` migration backfilling existing rows. API tests no longer send it.

- Every fork security invariant is preserved and re-verified against the merge (127/127 backend tests, 10/10 frontend tests, `vite build`, and `tests/security-invariants.mjs` green): an anonymous missing session is still a 403 at route permission checks rather than upstream's 401 (rejected sessions remain 401); the login, refresh, and OIDC rate limiters and the OIDC `no_redirect` cookie handling are unchanged; gravatar fetching stays bounded (5 s timeout, 1 MiB cap) with avatar cleanup and login-time backfill; the one-time setup-token gate and its field whitelist are kept, and upstream's open `POST /users/setup` endpoint was not taken. `multer` 2.3.0 and `mysql2` 3.24.3 stay fork-side; the remaining upstream dependency bumps that were younger than the `minimumReleaseAge` window were rejected and age out through the renovate cron.

- Took the next upstream round through `bb347a39` after the scheduled upstream-sync run fail-closed again on the same dep-policy collision: the lua-nginx-module build bumps to v0.10.32rc5 (resolver_conf_parsing 1.31.6 was already on develop), and the `react-intl` 12.0.2 / `markdown-to-jsx` 9.10.3 bumps (both published within 24 hours of the run) are rejected under `minimumReleaseAge` and left for the renovate cron.

See the [release notes](.github/release-notes/v2.15.1-mangyan1.rc.7.md) for installation and validation guidance.

## v2.15.1-mangyan1.rc.6 - 2026-09-15

Sixth public release candidate of the security-focused fork.

### Added

- Merged the rewritten upstream develop through `ec092c26` after the scheduled upstream-sync run stopped on conflicts (its intended fail-closed behavior). Integrated upstream's avatar rework: gravatar images are now cached per user id with magic-byte image-format detection and stale-extension cleanup, instead of being keyed by the email hash. The fork's hardening is retained: the 5-second bounded fetch, 1 MiB bounded body read, and login-time backfill for accounts seeded without an avatar. Initial-admin seeding now goes through the same user-creation path (permissions, password hashing, and audit logging included) instead of raw table inserts.

- Setup-mode user creation now applies upstream's strict field whitelist (only `name`, `nickname`, `email`, `auth`, with `roles` forced to admin) alongside the existing one-time setup-token gate, setup race guard, and token removal. The create-user schema rejects malformed `auth` objects. Upstream's refusal to start on Unraid app-template deployments and its stricter root/`UID`/`GID` env checks are included; standard Compose deployments are unaffected.

### Fixed

- Reduced hot-path overhead in the admin API and nginx config generation. Permission checks no longer rebuild an Ajv validator per request (measured at ~4.7ms per check, now a cached compiled validator for the 40 static permissions; the `users-*` permissions keep their per-request rebuild because they embed the calling user's id enum, which must never be cached across users). Nginx config rendering shares one Liquid engine and caches parsed templates instead of re-reading and re-parsing each template per host, and bulk access-list regeneration no longer repeats that per host. Authenticated avatar and gravatar images allow a five-minute private browser cache, so UI re-renders stop re-running the auth subrequest (JWT verification plus session and user queries) for every image on every render; the first fetch still requires an authenticated session and failed checks remain uncacheable.

- SQLite connections now wait out transient write contention with a five-second busy timeout instead of surfacing `SQLITE_BUSY` to a request, and keep a 20 MiB page cache so the small admin database mostly serves from RAM. Verified against the real driver build (Linux `better-sqlite3` 13.0.3, VACUUM and the backup/restore WAL replay unaffected). The `mmap_size` pragma was evaluated and excluded: `better-sqlite3`'s `pragma()` API whitelists a fixed set of pragmas and silently ignores others, so `mmap_size` set through it never applies (the underlying SQLite build does include mmap support); with the database already resident in the page cache, enabling it through a different mechanism would buy nothing for this workload.

- Added enforced guardrails against the two mistake classes found in one day of performance work: `.github/CODE_GUIDELINES.md` gives every coding session the security invariants, change discipline, and verification ladder as constraints rather than prose; `tests/security-invariants.mjs` runs in `lint-and-format` and fails the build on drift in five load-bearing properties (subprocess output reaching API responses, the jwtdecode 401-for-rejected-session contract, the no-store policy on the admin index and SPA fallback, the permission-cache identity exclusion, and the bounded-fetch timeout/byte-cap contracts). Every checker rule was negative-verified before being trusted: each guarded file was sabotaged with its real drift pattern, the rule had to catch it, and the tree was restored.

- Separated automatic session/profile reads from failed password/account-change rate limits, preserving bounded read traffic and the five-failure credential limit. Failed profile loading now shows recovery controls instead of a partial menu; HTML 401 responses clear expired sessions before JSON parsing.

- Run enabled CrowdSec/AppSec access checks before generating the built-in forbidden page, retaining original request methods and bodies. Added Docker coverage using the actual NPMplus bouncer with controlled LAPI/AppSec fixtures to the boot-resilience workflow.

- Restricted the built-in forbidden page with a stylesheet-hash Content Security Policy and framing denial, with regression coverage for hash drift and isolation from Custom HTML.

- Added a built-in Animated forbidden page (403) option under Settings > Default Site, with self-contained shield animations, a motion toggle, and reduced-motion support. Existing default-site selections and custom HTML remain available.

- Updated operator and maintenance documentation for release versus develop updates, one-time session renewal, Argon2 hash migration and rollback compatibility, and attack-evidence limits. The website now identifies its rolling develop installer; README guidance no longer directs current develop installations back to RC5.

- Integrated upstream develop through `3d5ac185`: Argon2id password hashing with legacy bcrypt migration and compatible MFA recovery codes, ECH updates without moreutils, and accurate CrowdSec bouncer identification. Retained reviewed dependency versions, bcrypt cost 6 for nginx basic-auth compatibility, central Express error handling, and CrowdSec telemetry instrumentation. Guarded legacy password migration against concurrent resets and fixed immediate-login/refresh timing after session revocation without future-dated tokens.

- Added attack evidence panels in CrowdSec history and active bans, with suggested attack types, retained WAF rule names and request paths, detection windows, sample limits, and explicitly spoofable User-Agent tool hints. Honeypot observations can load bounded same-IP alert context; WAF rule summaries distinguish aggregate matches from per-request evidence. Query strings and fragments are removed from request URI metadata.

- Took the first dependency batch that aged past the pnpm `minimumReleaseAge` supply-chain window after the upstream merge: `@biomejs/biome` 2.5.12 (both apps), `@types/react-dom` 19.2.7, and `react-intl` 10.1.26 (verified 8 days published; its `@formatjs` transitives were already pinned in the lockfile). The lockfiles regenerate clean under the policy, pnpm removed the now-stale `@biomejs/*@2.5.11` `minimumReleaseAgeExclude` entries, and biome 2.5.12 produces byte-identical formatting with unchanged findings. The remaining upstream-merge rejections (`react` 19.3.0, `vite` 8.3.0, `mysql2` 3.24.4, etc.) age out over the coming week.

- Added HTTP-level characterization tests for the merged session-revocation semantics: a self password change issues a fresh cookie and kills the pre-change session (401), refuses the change without the current password, an admin rotating another user's password does not refresh the admin session, a self session revoke clears the session cookie and sets the `__Host-npmplus_oidc_no_redirect` opt-out, revoking another user's sessions requires admin and leaves the caller's cookies alone, and revocation is enforced per-request. The tests document the whole-second `iat` granularity (a login in the same second as a revoke is born dead; the self-service refreshes add `iat+1` to cross it) and budget the users-route failure rate limiter.

- Added Anubis challenge outcomes for 1h/6h/24h/7d, paginated host/location configuration coverage, and a retained observation/ban-attempt ledger with IPv6 support and current-ban correlation. Installer v1.58 collects metrics without publishing port 9090 and journals bridge results. See [Anubis reporting definitions and limits](docs/anubis-reporting.md).
- Added Anubis status timestamps, HTTP response evidence, retained honeypot log counts, and the ban bridge's last-run status, accepted/failed commands, and pending bytes. The modal distinguishes log entries from timed catches and command acceptance from traffic enforcement.
- Added **Explore older alerts** to Attack activity: bounded cursor batches can browse beyond the recent-history sample, with per-batch counts, empty-batch navigation, signed expiring cursors, and explicit stops at dense timestamp or session limits. Overview sampling is unchanged. Added IPv6 search/display coverage and a real nginx test proving an IPv6 visitor decision can block a request carried over IPv4 from a trusted proxy. See [extended history and IPv6 guidance](docs/security-history.md).
- Added windowed WAF reporting by proxy host and timestamped enforcement observations to the CrowdSec WAF and System tabs. nginx ban/challenge actions and IPv4 firewall drop counters remain separate, with explicit stale, incomplete, and unavailable states.
- Installer v1.56 supplies a read-only host firewall observer. The image exports bounded nginx counters through a private Unix socket; the backend retains five-minute deltas for seven days in the existing application database. See [telemetry definitions, deployment requirements, and limits](docs/security-telemetry.md). These changes require both the updated image and installer and are not included in RC5.

### Fixed

- Fixed logout replay by tracking refresh sessions in the existing database. Ordinary logout revokes its session and MFA challenge while preserving other devices; existing users must sign in once after upgrading.
- Removed internal command diagnostics from API error responses, bounded and deduplicated attack-map geolocation reads, and added `HOME_GEOLOCATION=false` to disable the external lookup.
- Fixed Azerbaijani locale flags, readable dashboard button states, mobile ban rows and toolbar behavior, and IP/CIDR/duration validation with field-specific feedback.

- Merged upstream develop (token revocation on password change, MFA enable, and backup-code regeneration; fresh session cookies on those self-service flows; an OIDC redirect opt-out cookie on self session revoke; CommandError debug payloads surfacing hidden certbot failures; Estonian and Azerbaijani locale content; and the admin-UI avatar/gravatar caching locations). Fork behavior kept: 401 is still reserved for a rejected session and 403 for permission denials on authenticated users (upstream's anonymous 403→401 conversion was not taken), the central error handler still stamps `request_id`, per-route Express 5 handlers stay free of redundant try/catch, and the admin UI index/SPA fallback remain `no-store` with scoped CSPs.
- Rejected the upstream dependency bumps that arrived younger than the pnpm `minimumReleaseAge` supply-chain window (backend `json-schema-ref-parser` 16.0.2, `mysql2` 3.24.4, `openid-client` 6.8.8, `biome` 2.5.13; frontend `@tabler/core` 1.5.1, `react` 19.3.0, `react-dom` 19.3.0, `react-intl` 10.2.0, `@types/node` 25.9.6, `@types/react` 19.3.0, `@types/react-dom` 19.3.0, `vite` 8.3.0, `biome` 2.5.13). The package manifests and lockfiles were restored to the reviewed versions that satisfy the policy; the renovate/dependency-updates cron will pick each package up once it ages past the window.
- Pointed the smoke-test installer self-check at the file under test. The setup script compares itself against SELF_URL (the published develop copy) before update runs, so a branch or PR that changes the script without bumping `SCRIPT_VERSION` always failed the update steps with "different content with the same SCRIPT_VERSION" - the guard was comparing the tested tree against develop by design. The workflow now rewrites `SELF_URL` to a `file://` URL over the exact script under test, so the stale-guard still runs (and still refuses a genuinely stale script) while branch-side script changes are exercised end to end. The production guard with the real develop URL is unchanged.
- Re-verified every container with a fresh Trivy 0.74.0 scan against the published digests: the rebuilt Caddy image now scans clean (zero high/critical across OS packages and Go modules; gRPC-Go 1.83.2 build-info confirmed), CrowdSec 1.8.1 and Anubis 1.27.0 carry only already-triaged upstream matches covered by the expiring 2026-10-04 baseline, and the enforcement gate reported zero uncovered findings. Removed the stale `CVE-2026-59890` exception entry that current scanner databases no longer report, refreshed the security report's scan table and Caddy resolution with the verified numbers, and documented the 2026-09-11 re-verification including the AppSec posture check (`appsec-default`, no bot-challenge config, so the WAF layer cannot challenge legitimate crawlers).
- Rebuilt the Caddy image against gRPC-Go v1.83.2 and accepted the same new xDS advisory (CVE-2026-84445 / GHSA-2v4p-qf9q-27wj) in the upstream CrowdSec and Anubis images through documented exceptions expiring with the existing 2026-10-04 baseline. The xDS server path is not configured in this stack; the fork Caddy image is fixed at the source pin.
- Tidied fork maintenance: isolated browser deployment recovery from the shared entry point, documented integration boundaries in [FORK.md](FORK.md), and extracted a tested upstream-sync script. Sync proposals explicitly target this fork, preserve existing proposals on conflicts, and reject concurrent branch updates instead of overwriting them.
- Clarified that WAF blocked requests count activity since CrowdSec started, while local decisions count currently active ban/CAPTCHA records. A blocked WAF request does not necessarily create an IP ban, so the dashboard now explains why the first count can be positive while the second is zero.
- Updated the Debian restore smoke fixture to serve a real HTTPS health response, satisfy the strengthened container health gate, and verify the complete snapshot layout. Restore failures now print their diagnostic log in CI.
- Honeypot bridge prefix fingerprints detect log resets that regrow beyond the previous cursor; failed entries remain pending. Reporting keeps missing metrics, stale observations, and current-ban lookup failures distinct from zero activity.
- Installer v1.57 preserves pending honeypot entries after a CrowdSec ban-command failure, prevents overlapping bridge runs, and publishes an atomic status file through the existing read-only log mount. Incomplete log lines remain pending. Anubis reachability now uses HTTP response headers, so an oversized challenge body cannot cause a false outage.
- Setup script v1.55 checks the public TCP listener separately from the admin health API, so a supported default 404/444 policy no longer blocks protected startup, safe updates, or restore.
- Restore shares the maintenance lock, stops writers before saving SQLite files and sidecars, includes access credentials and custom HTML, and recovers the saved state on failure. Backups support installations without CrowdSec and fail when the consistent NPMplus database copy fails.
- Backend API, DNS-certificate, and smoke tests use isolated temporary databases and files. Concurrent MFA recovery-code submissions can consume a code only once.
- CrowdSec pagination reports complete bounded match totals and safe page limits. Dashboard reporting distinguishes exact, capped, unavailable, and stale data; aligns rolling activity with LAPI alert start times; separates parser events from node evaluations; and describes WAF rule triggers and bouncer API reads accurately.
- Added restore-failure and reporting regression coverage.

See the [release notes](.github/release-notes/v2.15.1-mangyan1.rc.6.md) for installation and validation guidance.

## v2.15.1-mangyan1.rc.5 - 2026-09-07

Fifth public release candidate of the security-focused fork.

### Added

- Turned up two of the three protection dials reviewed on 2026-09-06: honeypot auto-bans last 7 days instead of 24h (a repeat offender is simply re-banned on every new pot hit), and the honeypot ban bridge moved into the shared host-tooling installer so it is refreshed on every `--update` instead of only at fresh setup. The anubis catch-all keeps the API-safe default (CI re-asserted the documented v2.15.1 decision), but a new `--update --enable-anubis-catchall` flag turns it on for an existing install without reconfiguring. AppSec stays on `crowdsecurity/appsec-default` on purpose: that config already ships base-config plus every vpatch and generic rule, the remaining hub appsec configs are bot-challenge variants rather than extra coverage, and the DoS collections are log-parsers that cannot fire on this AppSec-fed stack.
- Added archive discovery to the setup script so migrations no longer need timestamp typing: `--restore` without a file searches `/var/backups/npmplus`, `/tmp` (the documented scp landing spot), and the current directory for archives and lists them newest-first, and an explicit `--restore` argument accepts any filename (the layout check is the gate), a directory (newest archive inside), or an unquoted glob. `--backup` now prints the ready-to-paste `scp` command with the real archive name plus a pull variant for copying from another LAN machine. Local coverage proves the /tmp discovery, directory, glob, renamed-archive, scp-hint, and nothing-found refusal paths; the picker only offers real `npmplus-*.tar.gz` archives, never unrelated files that merely share the prefix.
- Added an on-demand backup action to the setup script (`--backup`, menu option "Create a backup now") for creating a fresh archive immediately - before a migration, after configuration changes, or whenever the newest state matters more than the daily 02:17 schedule. It runs the same helper as the daily cron and prints the new archive's path and size.
- Added a restore action to the setup script (`--restore [FILE]`, menu option "Restore a backup from an archive") that applies a daily-backup archive onto an installation: it validates the archive layout, snapshots the replaced state, restores the database, certificates, access lists, CrowdSec state, and optional Anubis policy, re-registers CrowdSec keys the LAPI rejects, and waits for the stack to become healthy. Data is restored while the current machine's Compose configuration (image digests, LAN binding, ports, admin secret) is kept, so a server migration is: fresh install on the new machine, copy an archive over, restore. The restore path is distro-agnostic, archives move freely between Debian and Ubuntu servers, and CI proves the full round trip on both distributions.
- Made the restore replay a SQLite write-ahead log carried by the archive: a WAL-mode database's live main file is stale without its `-wal`, so restoring only the main file silently dropped the newest writes. The consistent hot copy remains preferred; the live-file fallback now replays its `-wal`/`-shm` companions on the next open (found by an end-to-end local restore test against the real image).
- Redesigned the CrowdSec overview around a scenario attack-mix donut with a clickable legend and a per-interval activity strip that highlights the current interval.
- Grouped the attack-mix donut by attack type instead of raw scenario: a scenario taxonomy maps every identifier to a readable label ("crowdsecurity/http-probing" becomes "HTTP probing") plus a coarse category (brute force, probing, injection, WAF blocks, suspicious clients, flooding, manual bans, honeypot catches, blocklist sync), unknown identifiers keep their raw name instead of guessing wrong, and legend entries open the attacks breakdown modal whose scenario list filters the Attack activity tab per scenario.
- Added an active honeypot bans table to the honeypot detail modal showing each ban's source, reason, and expiry time alongside the recently-caught trap addresses, so a honeypot catch is readable as a real ban with a lifetime instead of just a count.
- Added a "Top triggered rules" section to the WAF tab listing the AppSec rules with the highest hit counts since CrowdSec last started, sourced from the AppSec metrics passthrough.
- Added a WAF verdict card to the CrowdSec overview showing AppSec blocked requests and the pass/blocked traffic split, with click-through to the WAF tab.
- Added bouncer enforcement status to the local-bans card: decision hits served to the proxy bouncer (`cs_lapi_decisions_ok_total`) prove bans are enforced, and a bouncer that never queries CrowdSec is called out instead of failing silently.
- Added top attacker IP filters and a top attacker IP list in the attacks detail modal.
- Labeled sampled insight windows as a lower bound: when the alert window exceeds the dashboard sample, the attacks figure gains a "100+"-style suffix and an info banner states the counts are a floor, so a truncated sample is never presented as a complete total.
- Gave users seeded without an avatar their gravatar back on login: the installer's initial-admin seed and restored archives insert the user row directly, bypassing the gravatar download that only ran on user create and update, so those accounts kept a blank avatar forever until an admin edited and saved them. A successful login now backfills the missing avatar in the background (never delaying or failing the login), and a failed fetch stays empty so the next login retries instead of freezing a wrong default into the row.
- Made the proxy host status dot reflect backend reachability, not just config validity: the dot previously turned green whenever the nginx config was valid, even when nothing answered on the forward destination, so a dead backend read as "online". Creating, updating, or enabling a proxy host now tcp-probes its forward host (3 second timeout, skipped for path/empty schemes, unix sockets, and upstream names) and stores the result in the host meta. The dot is now green = reachable, orange = unreachable with the connect error on hover, yellow = disabled (moved off orange so disabled and unreachable cannot be confused), and red = nginx config invalid with the nginx error on hover. Probing happens at save time, so a backend that dies later keeps its last state until the next edit. Other host types keep the old config-validity dot.
- Made the attack map fly its meteors from the observed origins toward the instance instead of just landing on each origin: the insights payload now carries the instance's own location (a `HOME_LATITUDE`/`HOME_LONGITUDE` env pair wins; otherwise the instance's public IP is geolocated once through ipwho.is, cached for a day, with a one hour backoff on failure), a green "your instance" marker is plotted, and each meteor departs from its origin dot toward that marker. When the location is unknown the map degrades to marking the origins as before. The meteors still do not represent network routes.

### Fixed

- Made the parser metric card work on CrowdSec 1.8: 1.8 renamed the parser counters (`cs_parser_hits_total`/`cs_parser_hits_ok_total` became `cs_node_hits_total`/`cs_node_hits_ok_total`), so the dashboard read a name that no longer existed and showed a permanent dash with a note claiming CrowdSec had removed the metrics entirely. The summarizer now reads the renamed counters first and falls back to the old names on older CrowdSec versions, and the no-data note no longer asserts the metrics were removed. An empty parser table on 1.8 simply means no parser has processed lines yet - the NPMplus stack feeds CrowdSec through the AppSec component rather than log acquisition, so the card can legitimately stay empty there.
- Renamed the Attack activity column that shows the attacked URI from "Offender" to "Target": the column relays CrowdSec's recorded target, so labeling it Offender made an attack entry read as the instance's own address being the attacker, while the Source column beside it already shows the offender IP.
- Excluded blocklist-sync bookkeeping alerts from the attack figures: the periodic community-blocklist "update : +N/-N IPs" alerts counted as attacks in the attacks KPI, the donut, and the activity strip, inflating local attack numbers on instances that only pulled blocklists. They remain visible in history and keep the community count accurate.
- Fixed the CrowdSec overview WAF verdict card painting over the top-ASN quick filters beneath it: the card was pinned to its row height while its content ran taller, so it spilled out of its column and covered the filters on every desktop width. The card now sizes to its content.
- Fixed the local active-bans figure double-counting Anubis honeypot bans: the honeypot bridge writes its decisions as origin `cscli`, which both the local-bans KPI and the honeypot card counted, so the two cards could show the same number. The insights endpoint now excludes the honeypot scenario from the local figure, and the dashboard prefers that count (the Prometheus gauge cannot split by scenario, so it stays a fallback only).
- Fixed the attack-spike warning firing permanently on busy instances: the activity histogram is built from a newest-100-alert sample, so once an instance exceeds that cap within the window the older buckets always read zero, the baseline collapses, and the latest bucket looks like a spike. Spike detection is now suppressed on truncated samples, since a sampling artifact cannot be told apart from a real spike.
- Fixed the CrowdSec attack figures reading a stuck "100" on attacked instances: the insights sample caps at 100 alerts, and the donut center, attacks KPI, and attacks modal displayed that cap as if it were the real total. They now show "100+" whenever the sample is truncated.
- Fixed expanded alert and ban detail rows being unreadable in the dark theme: both tables hardcoded a near-white background for the expanded row while theme text stayed light. The rows now use the theme-aware secondary tint, and the dashboard toolbar lost its duplicate ban button (the Active Bans tab and per-row ban actions remain).
- Softened the attack-map meteors from straight orange sticks to slightly curved trails that fade tail-to-head.
- Fixed the whole public stack (NPMplus, Anubis, honeypot) staying dark after a reboot that followed a migration restore: the restore replaces the CrowdSec LAPI database wholesale, so the new machine's host firewall bouncer key - registered at fresh-install into the LAPI the restore then throws away - is rejected after the next reboot, the protected boot gate fails its bouncer check, and the raw-table boot guard never lifts. The restore now re-registers the host firewall bouncer key exactly like the admin UI keys, and the daily key-heal cron gained the host bouncer as a fourth section (previously it healed only the UI and nginx keys), re-attempting the protected startup so a bouncer that was dead at boot reopens the public ports without an operator. Verified per path: a dead key heals and rewrites the config, a working key is left untouched, and a machine without the installer-managed bouncer skips entirely.
- Fixed the safe-update preflight falsely aborting with "CrowdSec firewall bouncer is not protecting both INPUT and FORWARD" on a healthy bouncer: the repair step checked the iptables rules in the same instant `systemctl restart` returned, before the bouncer had reached LAPI and created its ipset, and `set -e` turned that transient gap into a full update abort (which also kept the installed script stale, since the wrapper refreshes it only on a successful run). The check now polls for up to ten seconds before judging the rule set.
- Fixed `command not found` errors during a restore's CrowdSec key healing: the four key helpers were defined after the early `--restore` dispatch, so bash could not resolve them. They are now defined before the restore code, and smoke coverage asserts every restore-called helper is defined before the dispatch. Cross-distro restores (Debian to Ubuntu and back) were always intended and remain supported.
- Updated the pinned checksum for Docker's official installer after its upstream script changed, so fresh Debian and Ubuntu installs no longer reject the verified `get.docker.com` download.
- Fixed a bash syntax error in the on-demand backup action's freshness check: it derived the archive's timestamp from the archive path (whose dots made it a non-numeric operand), printed a scary `syntax error: operand expected` while still reporting success, and the check never actually ran. The verification now keeps find's mtime and path fields separate and fails closed on any shell error. Smoke coverage now asserts the backup output contains no shell errors so a masked failure like this cannot pass silently again.
- Fixed the proxy host create response and audit log carrying stale meta without the nginx online status: create discarded the meta returned by the nginx configure step (update already captured it), so a freshly created host reported no state until the list refetched.
- Fixed the CrowdSec overview attack-mix legend colliding with the neighbouring WAF and attack-map cards on narrow desktop columns: the legend now truncates long scenario names with an ellipsis inside its card, the donut shrinks instead of overflowing, and large center totals step their font size down so they never touch the label. Also resized the site-menu icons so they no longer overhang the menu titles.
- Preset the OS alongside the distro when installing CrowdSec's packagecloud repository so the installer works on every supported distro; packagecloud only auto-detects when both are unset.
- Made the CrowdSec apt suite pick a published suite per distro, including a published fallback on Debian trixie, and repaired unpublished suite entries.
- Made the CrowdSec doctor explain an enrolled-but-empty CAPI pull and print the current Prometheus settings when the decision gauge is missing.
- Probed CrowdSec metrics from inside the NPMplus container and explained a missing community blocklist count instead of a bare dash.
- Refused CrowdSec key re-registration while the LAPI is unreachable so unclean state is not overwritten.
- Adopted the legacy installer bouncer safely, removed the stale bouncer backend override, and allowed the documented backup-free uninstall path.
- Removed a protected-service discovery race, stabilized the protected startup probe, and guarded public ports before Docker starts.
- Made the daily upstream-sync workflow report merge conflicts through the job log and step summary instead of hard-failing when the repository has issues disabled, and merged the latest upstream develop while keeping the fork's dependency pins under the seven-day supply-chain policy.

### Security

- Hardened public startup behind CrowdSec availability so services do not come up unprotected.

### Changed

- Restored upstream NPMplus runtime Certbot DNS-plugin installation so Cloudflare and other DNS challenges work out of the box; pinned pip and Certbot stay in the image and the pip packaging-tool scan findings are carried under a reviewed, expiring `.trivy/npmplus.yaml` baseline.
- Refactored the internal code layout without behavior changes: the CrowdSec LAPI client moved to its own module, the redundant per-route error handling that Express 5 already performs was deleted, the frontend API transport is generically typed, and the CrowdSec dashboard was split into per-tab components. HTTP-level characterization tests now pin the auth, CRUD, CrowdSec route, and DNS-challenge certificate contracts before any future change can drift them, and the backend entrypoint is pinned to LF so local Windows image builds boot.

See the [release notes](.github/release-notes/v2.15.1-mangyan1.rc.5.md) for installation and validation guidance.

## v2.15.1-mangyan1.rc.4 - 2026-09-05

Fourth public release candidate of the security-focused fork.

### Fixed

- Made the installer-managed LAN dashboard listener survive reboots with `FreeBind` and explicit network-online ordering, and migrated existing RC3 listeners during safe update.
- Fixed the host CrowdSec firewall-bouncer configuration rejected by current packages because its required logging mode was absent.
- Added Ubuntu firewall-bouncer service-mode support.
- Made fresh installation fail visibly when the firewall bouncer does not validate or start, instead of silently continuing without kernel-level enforcement.

### Changed

- Added a bounded systemd startup gate so the host firewall bouncer waits for the containerized CrowdSec LAPI after reboot.
- Updated Compose hardening syntax to the current `no-new-privileges=true` form and added CI coverage for both reboot defects and their upgrade repairs.
- Expanded the CrowdSec doctor and boot trace to report the LAN listener and firewall-bouncer configuration, status, and boot logs.

See the [release notes](.github/release-notes/v2.15.1-mangyan1.rc.4.md) for installation and validation guidance.

## v2.15.1-mangyan1.rc.3 - 2026-09-05

Third public release candidate of the security-focused fork.

### Fixed

- Fixed a reboot failure caused by an old NPMplus container retaining the deleted one-time administrator-password mount from `/run`.
- Made fresh installations remove bootstrap credentials safely by recreating NPMplus from the sanitized Compose configuration before deleting the temporary secret, and added automatic repair of affected existing installations during safe update.
- Made the integrated and standalone CrowdSec doctor report Docker startup failures before secondary key checks.

### Changed

- Hardened CrowdSec, Anubis, and Caddy containers with read-only root filesystems, dropped Linux capabilities, `no-new-privileges`, bounded temporary storage, and service health checks.
- Updated the custom Caddy build dependencies, disabled its administration endpoint and configuration persistence, and moved its runtime to an unprivileged user.
- Expanded CI to cover installation, Docker restart, failed-update rollback, database integrity, uninstall, clean reinstall, and another restart.

### Security

- Added release gates for the exact recommended Caddy, CrowdSec, and Anubis images on AMD64 and ARM64, plus identity-backed attestations for release assets and container images.

See the [release notes](.github/release-notes/v2.15.1-mangyan1.rc.3.md) for installation and validation guidance.

## v2.15.1-mangyan1.rc.2 - 2026-09-05

Second public release candidate of the security-focused fork.

### Fixed

- Repaired fresh Anubis honeypot file mounts and native CrowdSec conflict handling.
- Made Docker startup wait for usable DNS and corrected LAN-only administrator access through the host listener.
- Simplified private-LAN installer questions and made host-networking guidance clearer.

### Changed

- Added explicit per-host Anubis protection controls and left the global catch-all challenge off by default for API, webhook, and licensing compatibility.
- Reduced the frontend entry bundle from about 1.05 MB to 463 KB by splitting the CrowdSec attack map and importing only supported locale flags.
- Clarified version-pinned release installation before the rolling `develop` channel.

### Security

- Kept CrowdSec community protection enabled while showing remote blocklist entries only as aggregate dashboard metrics.
- Moved GoAccess executable code to administrator-protected same-origin assets, removed executable inline-script permission, and disabled caching of report data.
- Filtered documented, expiring upstream container exceptions out of open SARIF alerts without weakening the failing vulnerability gate.

See the [release notes](.github/release-notes/v2.15.1-mangyan1.rc.2.md) for installation and validation guidance.

## v2.15.1-mangyan1.rc.1 - 2026-09-04

First public release candidate of the security-focused fork.

### Added

- One-command interactive installation and maintenance for Debian and Ubuntu.
- Transactional updates with health checks, rollback snapshots, daily backups, reboot diagnostics, and CrowdSec credential repair.
- CrowdSec AppSec, firewall-bouncer, Anubis, and honeypot integrations with dashboard monitoring.
- A compact security dashboard with local alerts, local bans, attack geography, engine health, AppSec metrics, and protected manual actions.
- Fork-owned multi-architecture release images, SBOM/provenance attestations, exact-image vulnerability gates, and checksum-protected installer assets.

### Security

- Loopback-only administration and security-service listeners by default.
- Temporary administrator bootstrap secrets instead of credentials stored in Compose.
- Digest-pinned deployment images and reviewed, expiring vulnerability exceptions for unmodified upstream components.
- Hardened session, browser, API, container, and host-maintenance defaults.

### Changed

- Documentation and project website are focused on a simple reverse-proxy and security appliance workflow.
- PHP-FPM deployment is intentionally left to the proxied application stacks.

See the [release notes](.github/release-notes/v2.15.1-mangyan1.rc.1.md) for installation and validation guidance.
