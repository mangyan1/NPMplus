# Codebase review fixes and CrowdSec reporting audit

Date: 2026-09-08. Reviewed baseline: `1f126b7b` on `develop`.
Installer changes: v1.55. These changes are not part of the published RC5;
the existing hold on further releases remains in effect.

The combined develop update also includes installer v1.58,
[observed enforcement and WAF history](security-telemetry.md),
[extended alert history and IPv6 verification](security-history.md), and
[Anubis outcomes, coverage, and retained observations](anubis-reporting.md).
Final combined validation passed: 98 backend tests, 45 API smoke checks,
15 Linux installer tests, 8 frontend tests, 68 browser checks, TypeScript,
production build, schema validation, lint, and whitespace checks. Validation
counts below describe the earlier review stage. No owner's VM was changed.

## Original findings and fixes

| Finding | Resolution | Regression evidence |
| --- | --- | --- |
| Public health probes reject the supported default 404/444 policy, blocking startup/update/restore | Probe the public TCP listener and the admin API separately. Container, LAPI, AppSec, and firewall checks remain in the protected paths. | A real listening socket without an HTTP success passes; a closed port fails. Installer syntax and ShellCheck pass. |
| Pre-restore copies can lose committed SQLite WAL data and ignore copy failures | Stop the stack before copying complete database directories and sidecars. Require every snapshot copy to succeed before replacing data. | A crash-left WAL commit survives the snapshot; a failed snapshot leaves the original database intact. |
| Restore omits actual access credentials and custom HTML | Include `access` and `html` alongside certificates and existing restored payloads. | Restore and rollback assertions compare database rows, password files, HTML, and certificates. |
| API tests can delete a real fixed-path database | Each worker creates its own temporary filesystem and native SQLite path. Test configuration fails closed without an absolute test root; inherited external DB settings are cleared. The manual backend smoke harness also creates its own database. | Full backend suite passes on Windows and in a Linux container as UID 1000 without writable production paths. DNS command assertions remain unchanged. |
| Backup fails when optional CrowdSec is absent | Include `/opt/crowdsec` only when it exists. Require a successful SQLite online backup and remove a stale previous copy before starting. | Backup without CrowdSec succeeds; failed online backup creates no archive containing an old database copy. |
| Restore races backup/update | Acquire `/run/lock/npmplus-maintenance.lock` before snapshot or mutation. | A held lock refuses restore before stopping services. |
| Concurrent MFA recovery-code submissions can both succeed | Update only if the stored MFA metadata still matches the exact snapshot that was verified. A losing concurrent request returns false. | Concurrent requests yield one success; replay fails; other codes and metadata remain intact. |
| Decision match totals and pagination caps are misleading | Fetch a bounded 500-record sample plus one sentinel. Filter before paging, return the complete bounded match count, and never offer a page beyond the supported bound. | Sixty records report sixty matches on the first page; the final 500-record page has no unusable next link. |

Restore also retains the pre-restore Anubis policy and host firewall-bouncer
configuration. If application, copy, or startup verification fails after mutation,
the exit handler attempts to restore those files and the saved application state.
Recovery copies are retained in a unique root-only directory. A failed recovery is
still an operator incident; the script cannot guarantee recovery from disk failure.
Layouts without published 443 must pass container health and the internal admin API.

## Dashboard reporting corrections

The audit traced values from the private LAPI/Prometheus requests through backend
normalization, React Query responses, and rendered cards, charts, and tables.

| Display | Definition and corrected behavior |
| --- | --- |
| Attacks observed, scenario mix, activity, rankings, map | Recorded alert sample for the selected rolling window. Excludes simulation alerts, blocklist synchronization records, and dashboard-created manual bans. Uses alert start time, matching LAPI's `since` filter. These are alert records, not a count of every malicious HTTP request. |
| Sampling notice | At most 100 raw alerts for overview analytics; a 101st record proves truncation. An oversized response falls back to 25 and always remains marked incomplete. Incomplete samples cannot produce spike notifications. |
| Activity strip | Covers the whole rolling interval, including the oldest partial clock hour/day. The one-hour summary reports its actual peak instead of zero. |
| Local active decisions | Current bounded LAPI decision records, excluding honeypot decisions and simulations. No fallback to the differently scoped Prometheus local total. A capped count displays a lower bound such as `500+`; an unavailable count displays an em dash. |
| Honeypot decisions | Count and detail-row limits are separate: up to 500 records contribute to the count, while the modal shows at most 25. Honeypot log reads use a bounded 256 KiB tail and validate complete IP addresses. |
| Active bans / alert history | Match totals describe the whole fetched sample, not just the current page. An incomplete sample displays “at least” and its warning. History samples up to 500 raw alerts before filtering. |
| Community entries | Aggregate decision records from labeled gauges. Missing origin labels produce unknown totals. This number does not verify present firewall or proxy enforcement. |
| Bouncer activity | Nonempty LAPI replies and API request counters. Dashboard reads contribute; neither counter represents blocked traffic. |
| Parser success | Prefer source-event counters when present; otherwise use node-evaluation counters and label the scope. Never combine the two families. |
| Whitelist matches | Successful node matches, not all events examined by whitelist nodes and not necessarily unique events. |
| WAF outcomes | Cumulative AppSec requests and blocks; the difference means “not blocked by AppSec,” without claiming forwarding by nginx or acceptance by another layer. Missing request metrics display unknown values and an unavailable chart summary. |
| Rule breakdown and policy | Counts rule triggers, which can include multiple rules per request and out-of-band evaluation. The policy description identifies installer defaults, not a live inventory of loaded rules. |
| Health and freshness | A metrics HTTP 200 without CrowdSec samples is unavailable. Failed initial loads show an error; failed refreshes label retained values stale. The overview timestamp identifies its oldest displayed source. Anubis reachability, log readiness, and LAPI availability remain separate. |
| Target / ASN / location filters | Prefer hostname metadata over URI metadata; match ASN numbers even when a name exists; reject out-of-range map coordinates. |

The time selector applies to alert activity. WAF and engine counters remain
cumulative since the producing CrowdSec process started; the UI now says so.
An exposed historical counter cannot prove that inspection is functioning now.
The existing lightweight map, five tabs, reduced-motion support, and local-only
unban controls are preserved.

## Primary-source cross-check

CrowdSec documents separate event/node parser families, whitelist success counters,
AppSec request/block counters, rule triggers, and LAPI API counters in its
[Prometheus reference](https://docs.crowdsec.net/docs/observability/prometheus/).
The counter scope and cumulative-period labels follow that reference.

The v1.8.1 [decision controller](https://github.com/crowdsecurity/crowdsec/blob/v1.8.1/pkg/apiserver/controllers/v1/decisions.go)
increments the nonempty-decision response counter on successful bouncer reads,
including dashboard reads. The [decision filter](https://github.com/crowdsecurity/crowdsec/blob/v1.8.1/pkg/database/decisionfilter.go)
supports limits and origins and excludes simulated decisions by default.
The [alert filter](https://github.com/crowdsecurity/crowdsec/blob/v1.8.1/pkg/database/alertfilter.go)
implements `since` against `StartedAt`; the chart and history now use that same
timestamp, with a fallback when a fixture or older response lacks it.

## Validation

- Backend: 76 Node tests, schema validation, and 40 real-router smoke checks against
  fake LAPI, Anubis, and Prometheus listeners. The suite also runs in a disposable
  Linux container with networking disabled as an unprivileged user.
- Installer: 10 executable Linux recovery tests using the actual installer fragments,
  temporary host directories, real SQLite/tar/flock, and a fake Docker boundary.
  Bash syntax, ShellCheck, and changed-workflow actionlint checks.
- Frontend: TypeScript, 8 Node tests, production Vite build, and 47 Chromium smoke checks.
  Browser checks cover missing metrics, capped counts, stale refreshes, initial
  outages, recovery, unban/manual ban, keyboard tabs, reduced motion, WAF controls,
  and desktop/390px/320px layouts. Screenshots are reviewed and stay ignored.
- Biome checks use each application's own configuration. Full CI-mode formatting
  is also checked in a disposable LF copy because this Windows checkout contains
  pre-existing CRLF differences; unrelated source files are not rewritten.

These checks verify implementation and controlled integration behavior. They do
not compare counts against the owner's live VM, reboot its systemd/network stack,
or constitute a new image scan or release. The production frontend build passes. MFA concurrency is exercised on the supported SQLite configuration;
the MySQL/PostgreSQL compatibility casts are not integration-tested here.

## Post-push CI correction

The installer smoke run `34261821162` failed in the Debian restore fixture after
commit `27175d84`. Its sleeping BusyBox container had neither a Docker health
check nor an admin API, so the strengthened restore gate correctly refused it.
The fixture also checked the old snapshot path instead of
`pre-restore-*/data/npmplus/database.sqlite`. The step's `errexit` handling hid
the restore log when the command failed.

The fixture now serves an actual HTTPS `/api` response and declares a health
check, waits for healthy before restoring, verifies the complete snapshot path,
and prints the restore log even on failure. Production restore checks remain
unchanged. The updated Debian 13 round trip passes locally through real Docker
and Compose, using synthetic database bytes and certificates. All 15 executable
Linux installer recovery tests also pass, including real SQLite WAL preservation
and rejection of running-but-unhealthy containers. Workflow validation and
ShellCheck for the changed step pass; full-workflow ShellCheck retains unrelated
existing SC2016/SC2024 diagnostics in earlier steps.

## Suggested next dashboard changes

Follow-up: items 1 and 2 are now implemented for develop. See
[observed enforcement and WAF history](security-telemetry.md) for the precise
counter definitions, retention policy, deployment requirements, and validation.
The original cumulative Prometheus cards retain their scope; the additions use
new local counter observations. Item 3 is now also implemented for develop as
[bounded extended-history exploration](security-history.md), with explicit
upstream paging limits and IPv6 reporting guidance.

1. **Actual enforcement telemetry:** add timestamped observations from the nginx
   and host firewall bouncers before introducing an “enforcement healthy” badge or
   blocked-traffic counter. Keep each layer distinct to avoid double-counting.
2. **Windowed and per-host WAF reporting:** collect successive counter snapshots
   with reset handling and a bounded retention policy. Current global cumulative
   counters cannot accurately answer “blocked in the last hour” or attribute
   requests to individual proxy hosts.
3. **Larger-history exploration:** if the visible sampling warnings occur often,
   add bounded cursor fetching or a deliberate metrics/history store. Do not
   silently raise payload limits or imply that sampled rankings are exhaustive.

Those are feature additions rather than prerequisites for displaying the current
data accurately. The corrections above are implemented without a new telemetry
database or another dashboard service.
