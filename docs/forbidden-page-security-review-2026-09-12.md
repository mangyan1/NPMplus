# Forbidden-page security review

Reviewed commit: `86a7dff139923580c32b458484983ee546ca0d3c`.

## Result

No directly exploitable vulnerability was identified in the built-in forbidden
page or its dedicated Nginx location. This is a scoped source review and local
routing test, not a guarantee of security or a penetration test of the live server.

## Findings

### FP-01 - Low: page-specific browser policy is absent

`backend/templates/default.conf:90` serves the built-in page without a dedicated
Content-Security-Policy or frame restriction. The policies on the admin server in
`rootfs/usr/local/nginx/conf/conf.d/npmplus.conf` do not cover this default server.
Custom operator configuration or an edge proxy might add policies; live response
headers were not inspected. Global configuration includes nosniff and removes the
Server header (`rootfs/usr/local/nginx/conf/nginx.conf:163`).

The page has no scripts, forms, privileged actions, or untrusted interpolation,
so this is defense in depth, not a demonstrated XSS or sensitive clickjacking
vulnerability. Recommend a policy restricted to this built-in response, blocking
scripts, connections, objects, forms, base changes, and framing while allowing its
inline stylesheet via a maintained hash. Do not apply it indiscriminately to
operator-provided Custom HTML or configured proxy hosts.

## Evidence and verification

- Inspected the complete self-contained HTML/CSS/SVG in
  `rootfs/usr/local/nginx/html/forbidden.html:1`. No scripts, external assets,
  active embeds, event handlers, forms, dynamic host values, credentials, admin
  links, domain inventory, or version identifiers occur in the page.
- `backend/templates/default.conf:91` returns a literal 403 and maps it to a fixed
  internal file location. Request paths do not select arbitrary filesystem files.
- `backend/internal/setting.js:15` checks settings:update permission. Selecting
  forbidden does not write custom HTML; that file write is confined to value html.
- Tested the actual forbidden location block and bundled file in disposable
  nginx:alpine, bound only to loopback. All 13 request cases passed: ordinary
  requests, encoded script/SVG input, raw and encoded traversal, an API-looking
  URL, direct internal-file access, a normalized path, POST, PUT, DELETE, OPTIONS,
  and HEAD. Host, X-Forwarded-Host, X-Original-URL, and X-Rewrite-URL values were
  supplied. No tested input was reflected and no local file content was disclosed.
  All body-bearing 403 responses exactly matched the bundled HTML. Traversal
  attempts returned 400; direct /forbidden.html returned 404 as intended by internal.
- The test harness exercised the dedicated location, not the full deployed TLS,
  ACME, custom configuration, admin API, CrowdSec, or firewall stack. No live-host
  request, denial-of-service load test, or browser-engine vulnerability audit was
  performed. The disposable container was stopped afterward.

## Protection boundaries

The page is a response for unmatched hosts, not authentication or an IP ban.
Configured hostnames still route to their own virtual hosts and need their own
access controls. ACME challenge handling remains a separate intentional route.
A 403 page cannot itself stop request floods. Animation executes in the visitor's
browser; the server serves a small static document. Existing CrowdSec, firewall,
TLS, and application protections must be evaluated independently.

No application code or deployment configuration was changed by this review.

## FP-01 remediation

Implemented a response-header CSP and X-Frame-Options DENY on the built-in
forbidden page's internal Nginx location only, including error responses via
always. The policy denies scripts, external resources, base changes, form
submissions, and framing; only the SHA-256-pinned inline stylesheet is allowed.
The HTML file is pinned to LF, and a regression test detects stylesheet/hash
mismatch and checks that other default-site choices remain unaffected.

Disposable Docker Nginx plus Chromium verification passed: actual HTTP 403 and
policy headers, matching stylesheet, running animation and pause control,
blocked injected inline script, blocked same-origin framing, and reduced-motion
behavior. Backend tests and the rendered-template regression test also passed.
Deployment requires an image containing these changes and regeneration of the
default-site configuration. Local verification does not establish live-server
coverage.

## FP-02 - Confirmed default-page inspection gap and remediation

A follow-up real-bouncer test confirmed that the original rewrite-phase return
403 bypassed access checks. Its internal error-page redirect was then ignored
by the bouncer's standard ENABLE_INTERNAL=false configuration. Unknown requests
were denied, but this path did not query LAPI or AppSec.

The forbidden location now issues its 403 in content_by_lua_block, after inherited
access checks. No global CrowdSec settings or upstream bouncer code were changed.
The internal redirect remains excluded, avoiding duplicate inspection. Controlled
fixtures with the actual image's Nginx, Lua bouncer, and telemetry wrapper confirm
LAPI-ban enforcement, AppSec-denial enforcement, original method/URI/host/body
preservation, and operation with CrowdSec disabled. This validates integration
with AppSec verdicts, not detection accuracy of a real AppSec ruleset. The host
firewall and the deployed server were not changed or tested here. HTTP/TLS early
rejections and ACME handling are unchanged; this fix covers the forbidden-page
location only. Per-proxy-host telemetry aggregation still excludes the default
server (host ID 0); do not interpret those dashboards as complete default-host
coverage.

The reproducible harness is tests/forbidden-protection.py and now runs in the
boot-resilience workflow against the candidate image from the same commit.
