# Anubis reporting and nginx security review

Reviewed on 2026-09-08 against the local develop tree after `1f126b7b`, the cached
develop image, upstream documentation/source, and the published container scan.
The reporting fixes below target develop and are not included in RC5.
The RC6 release hold remains. The owner's VM was not accessed.

## Findings and changes

### ANU-01 — medium: failed honeypot bans were permanently skipped (fixed for develop)

The generated `anubis-honeypot-ban` helper ignored a failed `cscli decisions add`
and advanced its byte cursor to the end of the log. A temporary CrowdSec outage
could therefore discard a catch without creating its intended seven-day ban.
See `setup-npmplus.sh`, the `install_host_tooling` honeypot bridge heredoc.

Installer v1.57 advances only over completed successful or explicitly rejected
log lines, stops at the first failed ban command, and retries that entry during
the next cron run. A nonblocking lock prevents concurrent bridge runs; cursor
and status files are replaced atomically. Incomplete final lines stay pending.
The successful prefix is not replayed after an ordinary command failure.

The helper writes `/opt/anubis-data/anubis/honeypot-bridge.json` through the log
directory already mounted read-only in NPMplus. It records last-run time, status,
accepted and failed commands, invalid lines, and pending bytes. These are command
results, not unique attackers or observed blocked requests. A crash between command
acceptance and cursor persistence can replay commands; exactly-once delivery is
not claimed. Previously discarded catches are not automatically recovered.

### ANU-02 — low: a large challenge response could look like an outage (fixed for develop)

`backend/routes/crowdsec.js` previously bounded and consumed the reachability
probe's response body. A responding Anubis instance could be marked down because
its challenge body exceeded that limit. The probe now records HTTP status as soon
as headers arrive and cancels the body. As before, any HTTP status means reachable;
only failure to obtain a response means down. This is not a `/healthz` check or a
successful challenge test.

### ANU-03 — reporting gap: reachability and address badges lack outcome evidence

The Honeypot decisions modal now shows status-check time, HTTP status, log
modification time, retained valid-entry/distinct-IP counts, and bridge evidence.
Failed or stale bridge observations receive a warning. Missing bridge evidence
is unknown, never a successful zero. Active-ban availability remains independent.
The backend validates the fixed-path status JSON within 4 KiB and marks observations
older than 7.5 minutes, or more than five seconds in the future, stale.

Log counts cover complete valid addresses within the final 256 KiB, with explicit
truncation. The displayed address list remains capped at 20; the active-ban table
remains capped at 25, with the existing bounded LAPI count semantics.

Anubis v1.27.0 batches, sorts, and deduplicates addresses before writing them,
resets the file at startup, and resets it again around 64 KiB. It writes addresses
without event timestamps. Consequently, entries are not request counts, order is
not precise hit chronology, and modification time is not an individual catch time.
The legacy byte cursor detects a smaller file, but a reset and regrowth beyond its
old offset between polls can lose entries. A durable event source is needed for
complete history and reliable catch-to-ban correlation. [Pinned Anubis writer](https://github.com/TecharoHQ/anubis/blob/v1.27.0/internal/honeypot/naive/naive.go).

## Does nginx mitigate CVEs?

The Dockerfile pins nginx 1.31.5 and AWS-LC 5.8.0. Running `nginx -V` in the cached
develop image confirmed those versions. nginx 1.31.5 is above the fixed mainline
versions in the currently published core advisories, including:

| Advisory | Fixed mainline version |
| --- | --- |
| CVE-2026-42533, map/regex overflow | 1.31.3 |
| CVE-2026-60005, slice disclosure | 1.31.3 |
| CVE-2026-56434, SSI use-after-free | 1.31.3 |
| CVE-2026-42530, HTTP/3 use-after-free | 1.31.2 |
| CVE-2026-42055, proxy v2/gRPC overflow | 1.31.2 |

Source: [nginx security advisories](https://nginx.org/en/security_advisories.html).
This version comparison covers those core advisories; it does not certify every
third-party module, dependency, proxied application, or deployed image.

The build includes stack protection, FORTIFY, RELRO and a non-executable stack.
The shipped nginx configuration uses TLS 1.2/1.3. CrowdSec decisions, AppSec rules,
and optional Anubis challenges add distinct protection layers. Application and
nginx patching remain necessary; WAF virtual patches cover supported matching
attacks and cannot protect against every CVE or a parser flaw reached before
inspection.

### NGINX-01 — medium residual exposure: AppSec deliberately fails open

`rootfs/etc/crowdsec.conf.original` and installer-generated configuration default
to `APPSEC_FAILURE_ACTION=passthrough` and `APPSEC_DROP_UNREADABLE_BODY=false`.
An AppSec failure can therefore forward requests, and unreadable bodies can pass
without body inspection. CrowdSec documents body-inspection limitations for
HTTP/2 and HTTP/3 requests without Content-Length. Proxy hosts/custom locations
can also bypass AppSec. These are material coverage limits, not proof that nginx
is misconfigured. [CrowdSec nginx configuration reference](https://docs.crowdsec.net/u/bouncers/nginx/).

The policies were preserved. A stricter deny/drop policy needs testing against
the actual applications, especially APIs, uploads, and streaming clients, before
rollout. The WAF view already reports the relevant policy values. Keep virtual
patch rules updated and check per-host exceptions; do not describe Anubis as a
general CVE patch mechanism.

## Container scan evidence

The [2026-09-08 Container Security run](https://github.com/mangyan1/NPMplus/actions/runs/34211090946)
passed its high/critical gate. Its downloadable reports still contain accepted
suppressed findings: 11 occurrences for Anubis, 18 across CrowdSec binaries, and
2 setuptools metadata findings for NPMplus. Occurrences are not unique CVEs.
Zero unsuppressed high/critical findings is not a CVE-free result.

Exceptions remain documented separately in `.trivy/anubis.yaml`,
`.trivy/crowdsec.yaml`, and `.trivy/npmplus.yaml`, expiring on 2026-10-04. Anubis's
private listener reduces direct exposure but still receives externally influenced
requests through nginx. Its upstream Go findings must not be dismissed as wholly
unreachable. No exception was added or extended for this review.

This was a review of published scan artifacts, not a new image scan. Confirm the
VM's running image ID/digest and `docker exec npmplus nginx -V` before applying
these conclusions to that deployment. Avoid sharing full `nginx -T` output: it
can contain private configuration.

## Recommended next dashboard additions

1. Collect bounded Anubis challenge metrics from its private metrics listener:
   issued/passed/failed outcomes and policy actions, with reset-aware time windows.
   Validate actual metric definitions before labeling ratios. Keep port 9090 private.
2. Show enabled proxy hosts and custom-location exceptions beside observed host
   traffic. Configuration coverage and verified challenge outcomes need separate labels.
3. Introduce a retained, timestamped catch ledger with a durable ingestion source,
   rotation detection, and accepted/failed/active-ban correlation. Record observation
   time separately if the source cannot provide event time. The current plain log
   cannot support accurate historical rates or guarantee lossless retry after resets.
4. Show image version/digest, last successful scan time, and accepted-exception
   expiry. A green service badge must not imply patched dependencies.

Follow-up: challenge counters, saved host coverage, and a retained timestamped
observation/attempt ledger are now implemented for develop. See [Anubis reporting](anubis-reporting.md)
for precise scope. This does not supply missing original hit timestamps, lossless
source history, per-host challenge outcomes, or the proposed image/scan dashboard.

## Validation

- 91 backend tests, schema validation, and 42 real-router smoke checks.
- 13 Linux installer recovery/observer tests, including an IPv4 successful prefix,
  a failed IPv6 ban followed by retry, partial-line retention, and locking.
- 8 frontend tests, TypeScript, production build, and 60 Chromium dashboard checks.
  Desktop and 320px Anubis screenshots were inspected; no browser errors occurred.
- Biome CI in the LF verification copy, ShellCheck, Bash syntax, translation key
  ordering, and whitespace checks are run alongside the application checks.

Fixtures do not replace a production update, a real attack/challenge exercise,
or verification of the owner's current host configuration.
