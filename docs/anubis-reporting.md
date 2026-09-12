# Anubis outcomes, coverage, and honeypot history

Implemented for develop on 2026-09-08.
Open **CrowdSec → Overview → Honeypot decisions**. The modal now includes challenge
outcomes, expandable host configuration, and observation/ban history. Existing
reachability, bridge status, retained log counts, and active decisions remain available.

## Detection evidence

On current `develop`, expand **Detection evidence** beside a honeypot history
event to load bounded recent CrowdSec alerts for that IP. Compare timestamps and
rule names: an alert for the same address may describe a different request.
Lookup errors remain unavailable, rather than being presented as no attacks.

The address ledger has no request path, User-Agent, or payload. Its timestamp is
the collector observation time; bridge acceptance records a ban command, and
active-ban status describes the current decision. None proves that the original
request was blocked or identifies its tool. Richer direct attribution needs an
additional logging integration; the dashboard does not reconstruct missing data.
See [attack evidence](security-telemetry.md#attack-evidence-details).

## Deployment

These changes need both installer v1.58 and an image containing the new backend
and frontend. They are not in RC5 and have not been deployed to the owner's VM.
The release hold remains in place.

The installer installs `npmplus-collect-anubis` with a one-minute cron. It resolves
the installer-managed Anubis container's bridge-network IPv4 address and reads its
private port 9090. No port is published and the application receives no Docker
socket, credentials, or extra networking capability. The helper atomically replaces
`/opt/anubis-data/anubis/anubis-metrics.prom`, readable through the existing log mount.
A five-second deadline and 512 KiB bound apply, including on older curl versions.
A failed read preserves the last file and its original timestamp, allowing stale
reporting rather than fabricated zeroes. Custom host-network Anubis deployments or
authenticated/custom metrics listeners need their own compatible collection setup.

The image runs an independent minute collector while the backend is running, even
when nobody has the dashboard open. Migration `20260908010000_anubis_reporting.js`
adds `anubis_sample` and `anubis_event` to the existing application database. Allow
two successful samples and a completed five-minute interval before expecting
windowed values. Retained history travels with the existing database backup.

The new helper and cron participate in safe-update snapshot/rollback and uninstall.
Installing a helper still uses atomic `write_root_file` replacement.

## Metric definitions

| Dashboard field | Anubis source | Meaning |
| --- | --- | --- |
| Challenges issued | `anubis_challenges_issued` | Issuances, including API and embedded methods |
| Successful validations | `anubis_challenges_validated` | Successful validation operations |
| Failed validations | `anubis_failed_validations` | Failed validation attempts counted by Anubis |

Definitions were checked against [Anubis 1.27.0 counters](https://github.com/TecharoHQ/anubis/blob/v1.27.0/lib/anubis.go)
and [the request handlers](https://github.com/TecharoHQ/anubis/blob/v1.27.0/lib/http.go).
The private listener and an issuance counter were also exercised in a disposable
Anubis 1.27.0 container. No owner's service or traffic was used.

These are independent operations, not unique visitors. Validation may occur in
a later time window than issuance; failed-validation counters do not count every
possible early rejection. No pass/fail percentage is inferred. Inactive metric
families can be absent until first used; missing families display an em dash.

The backend stores per-series baselines and five-minute deltas for seven days,
with 1h/6h/24h/7d views. Process epochs, decreasing/disappearing series, and gaps
over 150 seconds invalidate the affected deltas. Epoch changes never convert
new process totals into historical traffic. Duplicate samples do not add counts.
Window boundaries are approximate to a collection interval; only completed buckets
are shown. Partial coverage and stale sources stay visible. The limits are 512 KiB
per scrape and 2,000 series per supported metric family; raw ASN labels are hashed
for baselines and never returned to the browser.

## Host coverage

The list pages through enabled, non-deleted proxy hosts in groups of 25. It reports
the selected default provider, custom upstream presence, and up to 25 custom
locations per host, with a truncation notice. An unset or `none` location provider
inherits the host provider, matching `backend/internal/nginx.js` rendering.

This is saved configuration, not live challenge verification. Advanced nginx
overrides are not interpreted, and custom upstream addresses are never exposed.
The existing auth-request template sends Anubis an internal Host header, while its
challenge metrics have no proxy-host ID. Consequently, instance counters cannot
be reliably attributed to individual configured hosts. Custom Anubis instances
are outside the installer-managed instance's metric scope.

## Timestamped observation ledger

The ledger distinguishes three records:

- **Address observed:** when the collector noticed a complete new address entry.
  It is not the original request timestamp. Initial log content establishes a
  baseline without pretending that old entries just arrived.
- **Ban command accepted:** the host bridge reported a successful command at the
  recorded time. This does not establish delivery or blocking of a client request.
- **Ban command failed:** the bridge reported a failed command; that entry remains
  pending for a later attempt.

The current active-honeypot-ban column is a separate, bounded LAPI lookup. Matching
IPv4/IPv6 identities are normalized. An unavailable or capped lookup yields unknown
for unmatched addresses; command success is never substituted for a current ban.

Anubis's [plain log writer](https://github.com/TecharoHQ/anubis/blob/v1.27.0/internal/honeypot/naive/naive.go)
batches, sorts, deduplicates, and resets addresses without writing event timestamps.
The backend persists a prefix fingerprint and position transactionally with its
events. Detected resets and collection gaps are marked; up to 1,000 new complete
entries are ingested per collection. A pending backlog remains visible.

Installer v1.58 also fingerprints the bridge cursor against an immutable bounded
snapshot, detecting resets even when the new file has grown beyond the previous
offset. Legacy byte cursors are retained and acquire a fingerprint on the first
nonempty run. The bridge preserves failed entries and journals each command result
with a timestamp and UUID in `honeypot-attempts.log`. The journal keeps the latest
2,000 attempts; the backend reads a bounded tail and deduplicates by record identity.
Journal recording is best effort and does not disable ban enforcement on a reporting
failure. Address and journal collector states are displayed independently.

The database retains the latest 20,000 observations/attempts for at most seven days,
served in 25-row pages. Pages are live and can shift as new records arrive. Repeated
IPs and retries are distinct observations, not new unique offenders. A crash can
replay commands; complete source generations or journal entries lost between polls
cannot be reconstructed. Identical rewritten prefixes can escape fingerprint
detection. This ledger provides durable retained observations, not a lossless
per-request audit trail or an hourly honeypot hit counter.

## API and validation

`GET /api/crowdsec/anubis-report?window=24&page=1&host_page=1` remains admin-only.
It returns independently scoped `metrics`, `ledger`, and `coverage` objects, with
sanitized fields, bounded pagination, current-ban correlation, and freshness states.

Verification covers 98 backend tests, 45 real-router smoke checks, 15 Linux
installer tests, 8 frontend tests, TypeScript, a production build, and 68 Chromium
checks. Browser cases cover unknown counters, window changes, location exceptions,
IPv6 history, initial outage/retry, stale refreshes, and mobile layout. Desktop and
320px screenshots were inspected. ShellCheck, Bash syntax, schema validation,
full Biome CI in an LF verification copy, translation ordering, and whitespace
checks passed. These local fixtures do not replace a VM update/reboot
check or a scan of a newly built image.
