# Security and CrowdSec dashboard review

Reviewed 2026-09-12 at `ae116fffde5237106bf80b7273c4148485dea53c`.

## Remediation status

All six findings below were remediated on 2026-09-12. The original findings and
reproductions below remain as the audit record. Deployment is a separate step.

| Finding | Fix |
| --- | --- |
| 1 — Logout replay | Persist session identities in the existing database; refresh keeps the identity and can only update an existing live row. Logout deletes the session and clears MFA challenge cookies. A racing refresh cannot recreate it. Other devices remain signed in. |
| 2 — Command diagnostics | Removed the debug response object; real HTTP regression coverage requires only the generic message and correlation ID. Server logs retain error diagnostics. |
| 3 — Geolocation | Added a 16 KiB streaming JSON limit, shared in-flight lookup, explicit opt-out, and corrected privacy documentation. Empty/null coordinates are rejected. Oversized declared bodies are canceled as well as streaming overflows. |
| 4 — Locale flag | Added AZ and a quiet globe fallback. |
| 5 — Ban controls/layout | Standardized outline/ghost variants, preserved readable disabled controls and accessible button attributes, and stacked mobile decision fields so targets, expiry and unban remain visible. Mobile toolbars scroll away and KPI spacing is smaller. |
| 6 — Ban validation | Validate real IPv4/IPv6 addresses, CIDR prefix ranges, and duration overflow before LAPI/auditing. The modal marks invalid fields and displays translated field names. |

**Upgrade behavior:** existing cookies lack the new session identity and require
one fresh login. The migration adds `npmplus_token_session`; it does not alter
certificate or protection configuration. Expired session rows are pruned on new
login. “Log out everywhere” and password-change revocation remain in effect.

Set `HOME_GEOLOCATION=false` to disable automatic map destination lookup. An
explicit valid `HOME_LATITUDE`/`HOME_LONGITUDE` pair still works without contacting
the provider. Automatic lookup otherwise discloses the server's public source IP
and NPMplus User-Agent to ipwho.is; it is cached for a day and failures back off
for an hour. No attack records or LAPI credentials are sent to that provider.

Validation after fixes: 112 backend tests, 8 frontend tests and TypeScript,
production build, API schema, real-router smoke, and all 72 browser checks pass.
Changed-file Biome CI checks pass (backend retains existing warning-level findings).
Browser verification
includes desktop/390px/320px, light/dark ban controls, malformed-ban feedback,
mobile rows, and the existing outage/authorization-related fixture flows.

## Original review summary

Two medium-severity security issues were reproduced: ordinary logout leaves a copied session usable and renewable, and command failures expose internal diagnostics. The latter regresses the previous SEC-006 resolution. One additional low-severity hardening gap exists in the map's external geolocation reader.

The CrowdSec dashboard has sound authorization and useful distinctions between detection, decisions, WAF outcomes, and observed enforcement. Its main browser flows pass, but the browser suite fails its console-error check because the Azerbaijani locale has no flag mapping. Visual review also found barely visible Active bans controls. Manual-ban validation accepts malformed addresses and CIDR lengths.

The initial review changed no application code. The subsequent fixes are recorded above. This is a targeted source review and controlled local verification, not certification that the entire repository or a deployed server is vulnerability-free.

## Security findings

### 1. Medium — ordinary logout does not invalidate the session

- **Rule:** EXPRESS-SESS-002 / server-side session termination.
- **Location:** `backend/routes/tokens.js:126`, `backend/internal/token.js:185`, `backend/lib/access.js:69`.
- **Evidence:** DELETE `/api/tokens` only clears the browser cookie and sets the OIDC opt-out cookie. It does not revoke the JWT's `jti` or change server-side session state. `getFreshToken` accepts the still-valid user token and issues another one-hour token.
- **Reproduction:** In an isolated temporary SQLite database, issue a valid synthetic user cookie, call DELETE `/api/tokens`, then replay the retained cookie. Logout returned 200; GET `/api/auth` returned 200; GET `/api/tokens` also returned 200 and issued a fresh session. The fixture explicitly sets the user's revocation timestamp to zero to avoid same-second migration defaults invalidating a newly created token.
- **Impact:** Someone who already obtained a session cookie can remain authenticated after the owner clicks ordinary Logout. Refreshing before expiry can extend access beyond the original hour. This finding does not establish a way to steal that cookie.
- **Fix:** Track and revoke the current session on logout, and carry revocation through its refresh lineage. A per-user revocation timestamp is a smaller implementation but logs out all devices; choose that behavior deliberately. Also clear any outstanding MFA challenge cookie.
- **Existing mitigation:** “Log out everywhere” uses the separate session-revocation endpoint. Password changes and explicit session revocation are covered by passing tests. HttpOnly, Secure, SameSite and signed cookies reduce cookie theft opportunities but do not invalidate a copied cookie.
- **Confidence:** Confirmed local HTTP reproduction. The presence of a separate all-sessions action does not make ordinary logout revoke its own session.

OWASP recommends active server-side invalidation on logout: [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

### 2. Medium — command-error diagnostics are returned to API clients again

- **Rule:** EXPRESS-ERROR-001.
- **Location:** `backend/app.js:72`, `backend/lib/utils.js:45`; representative caller: `backend/routes/nginx/certificates.js:273`.
- **Evidence:** For `errs.CommandError`, the central handler adds `payload.debug = { stack: err.stack?.split("\n"), previous: err.previous }`. The command wrapper attaches the original child-process error as `previous`, including enumerable command/output properties.
- **Reproduction:** Invoking the real central handler with a synthetic CommandError produced both the generic `Internal Error` message and a debug object containing a stack and the synthetic nested stderr marker.
- **Impact:** A user authorized to trigger a failing command can receive internal paths, command arguments, and subprocess output. Secret exposure depends on what that subprocess writes; no real secret was used or demonstrated in this review. This is not evidence of anonymous command execution.
- **Fix:** Remove raw stack/previous fields from the public response. Preserve correlation IDs and log diagnostics server-side. If certificate troubleshooting needs client-visible detail, return a deliberately selected and redacted summary. Add an HTTP regression test for command failures as well as ordinary errors.
- **Existing mitigation:** Certificate operations retain permission checks. The generic error message alone is insufficient while the debug object remains attached.
- **Confidence:** Confirmed handler reproduction and source trace. Upstream commit `6107d327` reintroduced this block. The existing root security report's SEC-006 “Resolved” statement is no longer accurate for this checkout.

### 3. Low — map geolocation bypasses the bounded response reader

- **Rule:** EXPRESS-DOS-001 / bounded external input.
- **Location:** `backend/internal/home-location.js:24`–`35`.
- **Evidence:** The fixed HTTPS `ipwho.is` request has a five-second abort timeout but uses `response.json()` without a byte limit. Other integrations use `readBoundedJson`. Concurrent cold requests also have no shared in-flight lookup.
- **Impact:** An oversized response from this external dependency could cause excessive allocation or parsing work in the backend. Exploitation requires control or abnormal behavior of that HTTPS dependency; a dashboard user cannot choose the endpoint. No practical exhaustion attack was attempted.
- **Fix:** Use a small streaming JSON limit, share the in-flight promise, and keep failure fallback independent of alert rendering. Add an explicit option to disable automatic geolocation.
- **Privacy correction:** The comment that “nothing about the server is sent anywhere” is inaccurate: the provider receives the source public IP and NPMplus User-Agent. Document the external lookup. Explicit HOME_LATITUDE/HOME_LONGITUDE already avoid it.
- **Confidence:** Confirmed missing bound; availability impact is conditional, not a demonstrated production outage.

## Dashboard findings

### 4. Low — missing Azerbaijani flag causes browser errors

- **Location:** `frontend/src/components/Flag.tsx:27`, `frontend/src/components/Flag.tsx:66`, `frontend/src/components/LocalePicker.tsx:35`.
- **Observed:** The actual Chromium harness repeatedly logs `No flag for country AZ found!` and exits with one failed check: the assertion that dashboard/host flows have no browser errors. The locale picker renders all locale options, so the error appears even with English selected.
- **Fix:** Add the AZ import/mapping and provide a quiet fallback for an unsupported code. Verify every offered locale resolves to a flag or the intended globe.
- **Classification:** UI regression, not a security vulnerability.

### 5. Low — Active bans controls are visually difficult to identify

- **Location:** `frontend/src/components/Button.tsx:46`–`53`; uses in `frontend/src/pages/Crowdsec/ActiveBans.tsx:122` and `:283`.
- **Observed:** The 320px screenshot shows an almost invisible refresh icon and effectively unreadable Previous/Next labels. The shared Button constructs separate `btn-secondary btn-outline` classes; compare the explicit `btn-outline-secondary` used by AttackHistory.
- **Fix:** Correct the shared outline variant composition and inspect enabled, hover, focus, loading, and disabled states in light and dark themes. Keep disabled labels legible even though disabled controls are exempt from some contrast requirements.
- **Additional usability limitation:** At 320px the table requires horizontal scrolling, and address/scenario text wraps awkwardly while right-hand columns are initially off-screen (`ActiveBans.tsx:153`). This is contained table overflow, not whole-document overflow. A compact mobile row with target, expiry and action visible together would reduce operator effort.
- **Classification:** Visual/operational usability issue. Screenshot inspection establishes the visibility problem; a full contrast measurement was not performed.

### 6. Low — manual-ban validation accepts invalid IP/CIDR values

- **Location:** `backend/lib/crowdsec-contract.js:9`–`34`, `backend/routes/crowdsec.js:549`.
- **Reproduction:** `validateManualBan({ value, duration: "1h", type: "ban" })` returns no errors for `999.999.999.999`, `192.0.2.1/99`, and `2001:db8::1/999`.
- **Impact:** Malformed operator input crosses the local validation boundary and is sent to LAPI, where rejection becomes a generic upstream error. It can also create a requested/failed audit entry instead of immediately explaining the invalid field. No injection or successful invalid ban was demonstrated.
- **Fix:** Validate addresses with `node:net` isIP, and require CIDR prefixes in 0–32 or 0–128 according to address family. Keep frontend validation consistent and handle unsupported duration values with field-specific feedback.

## Dashboard assessment

The desktop overview is readable and the five tabs give the operator a clear progression from summary to attack history, active decisions, WAF, and system evidence. KPI explanations correctly avoid adding WAF requests to active decisions. Cumulative AppSec blocks are a counter, consistent with the [CrowdSec Prometheus reference](https://docs.crowdsec.net/docs/observability/prometheus/).

Strengths verified in source and/or controlled tests:

- CrowdSec routes enforce administrator access; anonymous and restricted-user cases are tested.
- Credentials stay in backend file readers. Browser requests cannot supply arbitrary LAPI or metrics URLs; shared fetches reject redirects and bound time/body size, except finding 3.
- Community decisions stay aggregate-only and cannot be unbanned from the ordinary local table. Local mutations retain exact-target validation and audit records.
- Missing metrics render unknown states, failed refreshes mark retained values stale, and restoration of metrics recovers the UI.
- WAF history distinguishes observed nginx responses from cumulative engine counters. Firewall observations remain packet counts, not HTTP request counts.
- Anubis separates reachability, log readiness, bridge command results and retained observations. It does not fabricate per-hit timestamps or a pass rate from independent counters.
- Keyboard tab navigation, reduced motion, and desktop/390px/320px layout checks pass. React renders the inspected event details as text; no raw HTML rendering sink was found in the dashboard.

Limits that should remain visible:

- Overview insights use a bounded 100-alert sample, with a 25-alert fallback and sampling labels (`backend/routes/crowdsec.js:80`). They are not an exhaustive attack census on a busy server. Active decisions are also bounded and report lower bounds when capped.
- On phones the summary is long and the sticky toolbar consumes substantial vertical space. Compact KPI spacing and a smaller toolbar would improve repeated incident checks.
- A responding service, selected host policy, or historical counter cannot establish current protection for every proxied application. This review did not generate attacks against the owner's server.

## Scope and verification

Source review focused on Express entrypoints, cookies/JWT/MFA, permission boundaries, command execution and error handling, upload limits, nginx admin configuration, CrowdSec/Anubis clients and collectors, dashboard rendering, and selected installer/CI trust boundaries. Installer restore staging/locking and atomic helper writes were inspected; Linux installer/reboot suites were not rerun. No full penetration test, secret-history scan, fresh container-image scan, or exhaustive review of every vendored dependency was performed.

| Check | Result |
| --- | --- |
| Backend `node --test test/*.test.js` | 104 passed |
| Backend real-router smoke | Passed with fake LAPI/Anubis/metrics services |
| API schema validation | Passed |
| Frontend `npm test` | TypeScript and 8 tests passed |
| Production Vite build | Passed; no large-chunk warning in this run |
| Chromium smoke | One failed console-error check, described in finding 4; other checks passed |
| Screenshot inspection | Desktop overview/WAF, 390px overview, 320px Active bans/Anubis |
| Targeted security reproductions | Logout replay/refresh and CommandError disclosure confirmed |
| `pnpm audit --prod --json`, both packages | Zero reported advisories at review time |

The dependency results cover the package advisory service's current production dependency findings, not container OS/Go/Python components or the separate expiring Trivy exceptions. Dark-theme visual quality and production nginx CSP behavior were not revalidated in the Vite browser run.

Recommended order: address findings 1 and 2 first; fix the bounded map lookup; then repair the flag, button styling, and manual-ban feedback. Keep certificate DNS-plugin behavior and protection defaults intact while making those changes.
