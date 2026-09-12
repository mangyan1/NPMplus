# Changelog

All notable changes to the NPMplus Security Fork are documented here. The fork uses release identifiers based on the bundled NPMplus version followed by a fork-specific sequence.

## Unreleased

### Added

- Added HTTP-level characterization tests for the merged session-revocation semantics: a self password change issues a fresh cookie and kills the pre-change session (401), refuses the change without the current password, an admin rotating another user's password does not refresh the admin session, a self session revoke clears the session cookie and sets the `__Host-npmplus_oidc_no_redirect` opt-out, revoking another user's sessions requires admin and leaves the caller's cookies alone, and revocation is enforced per-request. The tests document the whole-second `iat` granularity (a login in the same second as a revoke is born dead; the self-service refreshes add `iat+1` to cross it) and budget the users-route failure rate limiter.

- Added Anubis challenge outcomes for 1h/6h/24h/7d, paginated host/location configuration coverage, and a retained observation/ban-attempt ledger with IPv6 support and current-ban correlation. Installer v1.58 collects metrics without publishing port 9090 and journals bridge results. See [Anubis reporting definitions and limits](docs/anubis-reporting.md).
- Added Anubis status timestamps, HTTP response evidence, retained honeypot log counts, and the ban bridge's last-run status, accepted/failed commands, and pending bytes. The modal distinguishes log entries from timed catches and command acceptance from traffic enforcement. See [the Anubis reporting and nginx review](docs/anubis-nginx-review-2026-09-08.md).
- Added **Explore older alerts** to Attack activity: bounded cursor batches can browse beyond the recent-history sample, with per-batch counts, empty-batch navigation, signed expiring cursors, and explicit stops at dense timestamp or session limits. Overview sampling is unchanged. Added IPv6 search/display coverage and a real nginx test proving an IPv6 visitor decision can block a request carried over IPv4 from a trusted proxy. See [extended history and IPv6 guidance](docs/security-history.md).
- Added windowed WAF reporting by proxy host and timestamped enforcement observations to the CrowdSec WAF and System tabs. nginx ban/challenge actions and IPv4 firewall drop counters remain separate, with explicit stale, incomplete, and unavailable states.
- Installer v1.56 supplies a read-only host firewall observer. The image exports bounded nginx counters through a private Unix socket; the backend retains five-minute deltas for seven days in the existing application database. See [telemetry definitions, deployment requirements, and limits](docs/security-telemetry.md). These changes require both the updated image and installer and are not included in RC5.

### Fixed

- Merged upstream develop (token revocation on password change, MFA enable, and backup-code regeneration; fresh session cookies on those self-service flows; an OIDC redirect opt-out cookie on self session revoke; CommandError debug payloads surfacing hidden certbot failures; Estonian and Azerbaijani locale content; and the admin-UI avatar/gravatar caching locations). Fork behavior kept: 401 is still reserved for a rejected session and 403 for permission denials on authenticated users (upstream's anonymous 403→401 conversion was not taken), the central error handler still stamps `request_id`, per-route Express 5 handlers stay free of redundant try/catch, and the admin UI index/SPA fallback remain `no-store` with scoped CSPs.
- Rejected the upstream dependency bumps that arrived younger than the pnpm `minimumReleaseAge` supply-chain window (backend `json-schema-ref-parser` 16.0.2, `mysql2` 3.24.4, `openid-client` 6.8.8, `biome` 2.5.13; frontend `@tabler/core` 1.5.1, `react` 19.3.0, `react-dom` 19.3.0, `react-intl` 10.2.0, `@types/node` 25.9.6, `@types/react` 19.3.0, `@types/react-dom` 19.3.0, `vite` 8.3.0, `biome` 2.5.13). The package manifests and lockfiles were restored to the reviewed versions that satisfy the policy; the renovate/dependency-updates cron will pick each package up once it ages past the window.
- Pointed the smoke-test installer self-check at the file under test. The setup script compares itself against SELF_URL (the published develop copy) before update runs, so a branch or PR that changes the script without bumping `SCRIPT_VERSION` always failed the update steps with "different content with the same SCRIPT_VERSION" - the guard was comparing the tested tree against develop by design. The workflow now rewrites `SELF_URL` to a `file://` URL over the exact script under test, so the stale-guard still runs (and still refuses a genuinely stale script) while branch-side script changes are exercised end to end. The production guard with the real develop URL is unchanged.
- Re-verified every container with a fresh Trivy 0.74.0 scan against the published digests: the rebuilt Caddy image now scans clean (zero high/critical across OS packages and Go modules; gRPC-Go 1.83.2 build-info confirmed), CrowdSec 1.8.1 and Anubis 1.27.0 carry only already-triaged upstream matches covered by the expiring 2026-10-04 baseline, and the enforcement gate reported zero uncovered findings. Removed the stale `CVE-2026-59890` exception entry that current scanner databases no longer report, refreshed the security report's scan table and Caddy resolution with the verified numbers, and documented the 2026-09-11 re-verification including the AppSec posture check (`appsec-default`, no bot-challenge config, so the WAF layer cannot challenge legitimate crawlers).
- Rebuilt the Caddy image against gRPC-Go v1.83.2 and accepted the same new xDS advisory (CVE-2026-84445 / GHSA-2v4p-qf9q-27wj) in the upstream CrowdSec and Anubis images through documented exceptions expiring with the existing 2026-10-04 baseline. The xDS server path is not configured in this stack; the fork Caddy image is fixed at the source pin. See [the container security triage](security_best_practices_report.md).
- Tidied fork maintenance: isolated browser deployment recovery from the shared entry point, documented integration boundaries in [FORK.md](FORK.md), and extracted a tested upstream-sync script. Sync proposals explicitly target this fork, preserve existing proposals on conflicts, and reject concurrent branch updates instead of overwriting them.
- Clarified that WAF blocked requests count activity since CrowdSec started, while local decisions count currently active ban/CAPTCHA records. A blocked WAF request does not necessarily create an IP ban, so the dashboard now explains why the first count can be positive while the second is zero.
- Updated the Debian restore smoke fixture to serve a real HTTPS health response, satisfy the strengthened container health gate, and verify the complete snapshot layout. Restore failures now print their diagnostic log in CI.
- Honeypot bridge prefix fingerprints detect log resets that regrow beyond the previous cursor; failed entries remain pending. Reporting keeps missing metrics, stale observations, and current-ban lookup failures distinct from zero activity.
- Installer v1.57 preserves pending honeypot entries after a CrowdSec ban-command failure, prevents overlapping bridge runs, and publishes an atomic status file through the existing read-only log mount. Incomplete log lines remain pending. Anubis reachability now uses HTTP response headers, so an oversized challenge body cannot cause a false outage.
- Setup script v1.55 checks the public TCP listener separately from the admin health API, so a supported default 404/444 policy no longer blocks protected startup, safe updates, or restore.
- Restore shares the maintenance lock, stops writers before saving SQLite files and sidecars, includes access credentials and custom HTML, and recovers the saved state on failure. Backups support installations without CrowdSec and fail when the consistent NPMplus database copy fails.
- Backend API, DNS-certificate, and smoke tests use isolated temporary databases and files. Concurrent MFA recovery-code submissions can consume a code only once.
- CrowdSec pagination reports complete bounded match totals and safe page limits. Dashboard reporting distinguishes exact, capped, unavailable, and stale data; aligns rolling activity with LAPI alert start times; separates parser events from node evaluations; and describes WAF rule triggers and bouncer API reads accurately.
- Added restore-failure and reporting regression coverage. See [the codebase review and dashboard reporting audit](docs/codebase-review-2026-09-08.md) for findings, metric definitions, validation, and follow-up recommendations.

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
