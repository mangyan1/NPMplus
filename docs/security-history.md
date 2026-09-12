# Extended alert history and IPv6 offenders

Unreleased develop addition, 2026-09-08. RC5 does not include it.

## Browse older alerts

In **CrowdSec > Attack activity**, choose **Explore older alerts**. **Next** reads
another bounded batch, **Previous** revisits the preceding batch, and **Restart
exploration** starts a fresh window. **Return to recent history** restores the
existing paginated view. Filters and the time selector remain available.

The ordinary recent-history view retains its 500-record sampling boundary. The
exploration path can go deeper without increasing that request or response limit:

- Each action requests at most 101 raw LAPI alerts, then processes at most 25
  previously unseen records. It returns only sanitized matching attack records.
  On an oversized primary response it retries once with 25 raw alerts. The existing
  12 MiB primary and 4 MiB fallback response limits remain enforced.
- Filters apply to the current batch. Zero matches do not prove that older batches
  contain no matches: use **Next** while available. Counts explicitly describe the
  current batch; they are not an exhaustive total for the selected window.
- Exploration fixes its start/end times and traverses recording time (`CreatedAt`)
  descending, breaking ties by alert ID. It preserves nanosecond precision. The
  attack-window test still uses `StartedAt`, matching the existing activity view.
- Cursors are signed, bound to the filters/window, and expire after one hour or a
  backend restart. One exploration allows at most 100 batches, or 2,500 processed
  raw records. An expired/changed cursor shows a restart message. No browser-side
  LAPI credential or arbitrary upstream URL is accepted.
- Exploration does not poll automatically. Previously visited batches can be
  cached for navigation; restarting starts a new query session. The upstream LAPI
  remains a live database, so retention/deletions or restores can change results.
  This is not an immutable export or a replacement alert database.

CrowdSec 1.8.1 accepts `created_before` as a **relative duration**, with an inclusive
recording-time boundary. Requests overlap by one second and apply the exact
timestamp/ID boundary locally to remove repeats. The backend and LAPI must have
synchronized clocks, as in the installer-managed containers on one host. Keep this
requirement in mind when using an independently hosted LAPI.

LAPI does not expose a corresponding alert-ID cursor. A very dense timestamp or
overlap interval can fill the bounded response with previously seen records. In
that case, or at the session batch limit, exploration stops with an explicit
incomplete-history warning. It does not jump past unseen records. Investigate the
remaining history directly in CrowdSec when this boundary is reached. Overview
charts and rankings keep their original sampling warnings and are not expanded by
this feature.

The authenticated endpoint is unchanged:
`GET /api/crowdsec/history/alerts?cursor=&window_hours=24` starts an exploration.
Use the returned `next_cursor` with the same filters for the next batch. The
response adds `scan_mode`, `scanned`, `start`, `end`, and `next_cursor`. Non-admin
and anonymous callers remain denied before any LAPI request.

## Read attack details

Expand an alert in **Attack activity**, or expand an alert associated with an
**Active bans** row. Current `develop` shows the exact scenario, a suggested attack
category, source network, detection window, and up to ten retained event records.
Recorded WAF rule names and request paths are preserved; URI query strings and
fragments are omitted. User-Agent hints describe a claimed client such as sqlmap
or curl, not a verified attacker identity. Unknown tools remain unknown.

The displayed event count and retained sample can differ. A rule match is not
proof of a successful exploit or an enforced IP ban. WAF top-rule counters are
aggregate matches, not individual attacker records. See [evidence limits](security-telemetry.md#attack-evidence-details).

## IPv6 visitors with an IPv4 origin

CrowdSec's nginx remediation component supports both IPv4 and IPv6 addresses.
The dashboard displays and searches either address family returned by LAPI.
These capabilities do not require an IPv6 socket on the NPMplus origin.

For example, an IPv6 visitor can connect to Cloudflare, which then connects to an
IPv4-only origin. nginx can evaluate the visitor's IPv6 decision when its real-IP
configuration correctly trusts that proxy and receives the original address.
An arbitrary client-supplied forwarded-address header is not sufficient evidence;
do not trust every source to supply it. The host firewall sees the proxy's network
address, while nginx can see the original visitor address. A provider's Pseudo IPv4
or header-rewriting configuration can change which identity reaches nginx.

Without a reachable IPv6 address, direct IPv6 traffic cannot reach the origin.
The installer enables the host firewall bouncer's IPv6 path when a global IPv6
address exists; it does not force IPv6 connectivity onto an IPv4-only machine.
The [new host firewall telemetry](security-telemetry.md) still measures **IPv4
packets only**. IPv6 offender reporting and nginx blocking are separate from that
packet counter coverage. Community IPv6 intelligence also does not prove that an
IPv6 visitor contacted this instance.

## Verification and references

Regression tests cover browsing all 650 fixture alerts without duplicates, empty
filtered batches, IPv6 searches, dense timestamp stops, oversized-response fallback,
nanosecond ordering, tampered/filter-mismatched/expired cursors, malformed timestamps,
and the admin gate. The real nginx/bouncer test now uses an IPv4 connection from a
trusted fixture proxy carrying `2001:db8::1234`; the IPv6 decision returns HTTP 403
and increases the HTTP ban action count without increasing AppSec policy bans.

Browser checks cover next/previous navigation, empty batches, IPv6 display, return
to recent history, and 320px layout. Screenshots remain ignored. These local tests
do not validate the owner's current proxy headers or deployment configuration.

Validation passed: 88 backend tests on Windows and unprivileged Linux, schema
validation, 8 frontend tests, TypeScript, production Vite build, the real
nginx/IPv6-over-IPv4 integration, and 57 Chromium checks. Desktop and 320px history
screenshots were inspected. Both applications pass full Biome CI in the disposable
LF verification copy, English translation ordering, and `git diff --check`.
These develop changes are not included in RC5. No VM deployment or new release has been performed.

- [CrowdSec alert filters](https://github.com/crowdsecurity/crowdsec/blob/v1.8.1/pkg/database/alertfilter.go)
  defines the duration-based time filters.
- [CrowdSec alert ordering](https://github.com/crowdsecurity/crowdsec/blob/v1.8.1/pkg/database/alerts.go)
  defines recording-time and ID ordering.
- [CrowdSec nginx bouncer](https://docs.crowdsec.net/u/bouncers/nginx/)
  documents IPv4/IPv6 support.
- [Cloudflare IPv6 compatibility](https://developers.cloudflare.com/network/ipv6-compatibility/)
  describes IPv6 visitors reaching IPv4 origins and Pseudo IPv4 behavior.
