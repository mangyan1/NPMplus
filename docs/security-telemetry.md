# Observed enforcement and WAF history

Implemented for develop on 2026-09-08 after the [reporting audit](codebase-review-2026-09-08.md).
This addition is not included in RC5 and does not lift the release hold.

## What the dashboard reports

The **WAF** tab adds a proxy-host selector and recorded totals for the selected
1h, 6h, 24h, or 7d window. The **System** tab adds separate nginx and host firewall
observations. Existing CrowdSec Prometheus cards remain cumulative engine metrics;
their totals need not match these observations.

| Observation | Meaning |
| --- | --- |
| Confirmed AppSec responses | The nginx bouncer received HTTP 200 or 403 from its AppSec request without a transport error. Includes allow and deny responses. |
| AppSec policy ban actions | The nginx ban plugin was invoked after AppSec rejected a check. Includes configured fail-closed and unreadable-body policy; it is not exclusively a malicious-request count. |
| AppSec response errors | Transport errors or AppSec responses other than 200/403. |
| Checks without an AppSec response | AppSec checks that returned before reaching the response observation, such as unreadable-body handling. |
| HTTP ban actions | Calls to nginx's CrowdSec ban plugin across managed proxy hosts. Includes AppSec policy bans and decision-based bans. |
| Challenge actions | Calls to CrowdSec captcha/challenge plugins. Does not count Anubis challenges. |
| IPv4 host / forwarded packets dropped | Increases in the installer-managed CrowdSec blacklist DROP/REJECT rule counters on INPUT / FORWARD, respectively. |
| Host firewall evidence | Timestamped service-active and required-rule-presence observations. This does not test LAPI synchronization, every firewall path, or continuous protection. |

Remediation calls are observed before the original plugin runs; they do not prove
that a client received a complete response. Application-generated HTTP 403s are
not counted as CrowdSec ban actions. Locations that bypass AppSec are not counted
as inspections. Neither request counts nor packet counts represent unique IPs.
Do not sum the HTTP and firewall figures. The firewall observer currently covers
IPv4 only, even on installations that also enforce IPv6 rules.

## Why WAF blocks can be 2 while local decisions are 0

The overview's **WAF blocked requests** value sums `cs_appsec_block_total` since
CrowdSec started. It counts requests, including repeated requests from one IP.
The **Local active decisions** card counts current local LAPI decision records,
excluding community feeds, simulations, and the separately displayed honeypot
decisions. Expired and removed decisions are no longer active.

AppSec can reject the current request without creating an ongoing IP ban; longer
remediation depends on scenarios and decision profiles. Therefore two WAF blocks
and zero local decisions can both be correct. Neither value counts unique
attackers, and the WAF counter alone does not prove current end-to-end enforcement.
See CrowdSec's [metric definitions](https://docs.crowdsec.net/docs/observability/prometheus/)
and [AppSec introduction](https://docs.crowdsec.net/docs/appsec/intro/).

The local card's subtitle describes active decisions. It no longer displays
cumulative nonempty decision replies beneath that count: those replies count API
responses, including repeated reads and dashboard reads, rather than blocked
requests or unique IPs. Bouncer API request statistics remain in the System tab.

The overview and WAF tab explain this distinction directly. These definitions
were checked against the backend and frontend; the owner's live server has not
been inspected as part of this clarification.

## Collection, retention, and limits

- The image instruments the pinned Lua bouncer at its AppSec HTTP response and
  wraps its remediation calls without replacing enforcement behavior. The build
  fails if the exact upstream insertion point changes. The private exporter uses
  `/run/npmplus-telemetry.sock`; no TCP listener or browser credential is added.
- nginx labels traffic with the numeric managed proxy-host ID. Arbitrary Host
  headers, IPs, URLs, payloads, and secrets are not stored. A 2 MiB shared dictionary
  limits observation to 200 host slots per nginx master lifetime. Capacity loss
  marks history incomplete. Deleted hosts remain identifiable by their numeric ID;
  displayed domain names come from the current proxy-host configuration.
- Installer v1.56 installs `/usr/local/bin/npmplus-collect-enforcement` and a
  minute cron. This read-only host helper writes aggregate firewall counters
  atomically to `/opt/npmplus/crowdsec/firewall-telemetry.json`. It requires the
  installer-managed firewall-bouncer marker. The backend receives the file through
  its existing data mount; no Docker socket or firewall capability is added.
- The backend samples both sources every 60 seconds independently of open browser
  tabs. It persists baselines and five-minute counter deltas in one transaction in
  the existing application database's `security_telemetry` table. No additional
  database service, external telemetry account, or frontend dependency is required.
- Data is retained for seven days, plus the current boundary bucket and baselines.
  Expired buckets are pruned on successful collection. Restarts of the backend
  cannot replay a saved delta. nginx master restarts and firewall service/boot epoch
  changes start new baselines; decreasing counters and gaps over 150 seconds skip
  the affected deltas instead of inventing traffic.
- Windows end at the last completed five-minute boundary. Each delta belongs to
  the bucket containing the end of its collection interval, so boundary timing is
  approximate to a collection interval (normally one minute, at most 150 seconds
  for an accepted interval). The dashboard excludes the current unfinished bucket.
- New installations need a baseline, another sample, and a completed bucket before
  counts appear. Missing intervals remain **partial history**. An observed zero is
  different from unavailable data, which displays a dash. After 150 seconds without
  a fresh observation, source status becomes stale and rule verification is withheld.
- The per-host response is bounded to 200 entries. Totals include other recorded
  hosts when history spans more IDs; a separate warning marks the truncated list.
  The dictionary capacity limit instead drops observations and marks history partial.

The admin-only `GET /api/crowdsec/telemetry?window_hours=24` endpoint exposes the
window, timestamps, coverage, per-layer totals, and bounded host list. Only the
existing 1/6/24/168-hour choices are accepted. Anonymous and non-admin requests
remain denied by the existing CrowdSec access gate.

## Deployment and operation

This needs both an image containing these changes and installer v1.56 or newer.
Updating only the UI cannot collect nginx traffic, and updating only the image
cannot install the host firewall observer. Once a corresponding image is published,
use the ordinary installer-managed safe update. Template version 21 regenerates
existing proxy configurations with their numeric telemetry IDs. Do not manually
expose the Unix exporter or mount the Docker socket into NPMplus.

For custom Compose installations, nginx/WAF history can work with the new image
while firewall observations remain unavailable unless equivalent installer-managed
host tooling is present. AppSec-disabled installations can still record decision
ban actions, while their AppSec response totals can legitimately remain zero.
Existing database backups include retained telemetry. Restoring an archive restores
its history; collection gaps after restore remain visible.

To investigate missing data, first check the dashboard's observation timestamps,
then the private socket, cron/helper installation, and the firewall snapshot's
`collected_at` value. A green process status or a nonempty LAPI decision reply alone
is insufficient evidence that traffic was blocked. No live VM deployment or reboot
has been performed as part of this change.

## Validation

Regression coverage includes real SQLite migration/persistence, duplicate samples,
counter resets, epoch changes, stale timestamps, gaps, host limits, pruning, and the
admin-only HTTP contract. Linux installer fixtures execute the actual generated
helper against known firewall rules. A disposable nginx integration test invokes
the real pinned bouncer with fake LAPI, AppSec, and upstream listeners, checking
allow/deny, upstream 403, bypass, and AppSec failure behavior.

Run from the repository, with a disposable image containing Python and nginx:

```sh
cd backend && pnpm test && node validate-schema.js
cd ../frontend && pnpm test && pnpm exec vite build
# From the repository root, on Linux:
python3 tests/installer-recovery.py
docker run --rm --network none --entrypoint python3 \
  -v "$PWD:/repo:ro" ghcr.io/mangyan1/npmplus:develop /repo/tests/telemetry-nginx.py
```

The nginx harness copies the instrumentation into its disposable container, so it
also works with the preceding image. Browser fixtures in
`backend/.smoke/ui-driver.mjs` cover host selection, partial history, missing data,
stale firewall evidence, and responsive layouts. Screenshots remain ignored.

Local verification passed: 81 backend tests (including an unprivileged Linux run),
schema validation, 40 backend smoke checks, 11 executable installer tests, the real
nginx/bouncer test including the production Unix exporter, 8 frontend tests,
TypeScript, and a production Vite build. The 53 Chromium checks cover desktop, 390px, and
320px layouts; the new WAF screenshots were inspected. Both apps pass full Biome
CI mode in a disposable LF copy, preserving unrelated Windows line endings.
Bash syntax, ShellCheck, Dockerfile lint with the repository's CI settings, English
translation ordering, and `git diff --check` pass. MySQL/PostgreSQL are not
integration-tested; the migration uses a larger text type on MySQL so buckets
spanning host turnover can exceed its ordinary TEXT limit.

These tests do not replace a final rebuilt-image scan or an operator check against
live VM traffic. These develop changes have not been deployed to the owner's VM or released.

## Primary references

- [CrowdSec remediation usage metrics](https://docs.crowdsec.net/docs/observability/usage_metrics/)
  distinguishes HTTP and firewall measurement units.
- [CrowdSec nginx remediation component](https://docs.crowdsec.net/u/bouncers/nginx/)
  documents AppSec and remediation behavior.
- [Pinned Lua bouncer source](https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/lib/crowdsec.lua)
  is the build-time response-hook contract. Recheck the hook and integration test
  whenever the bouncer revision changes.
