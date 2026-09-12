# Unknown-host forbidden page

Select **Settings > Default Site > Animated forbidden page (403)** and save.
The built-in page always responds with HTTP 403 when a request reaches the
configured default page. No HTML or status-code entry is required.

The [page source](../../rootfs/usr/local/nginx/html/forbidden.html) is a complete,
self-contained document with inline SVG and CSS. It includes a motion toggle,
respects reduced-motion preferences, and requests no external assets.
It does not claim that the visitor is an attacker or that their IP is banned.

Existing selections are preserved until you save a different option. This page
does not replace configured proxy hosts or CrowdSec block responses. Existing
HTTP and TLS rejection rules still apply; rejected connections cannot display it.
See the [operations guide](../setup-npmplus.md).

For your own design, copy the source into **Custom HTML**, customize it, and set
its HTTP status code to **403**. Custom HTML remains available independently.

When CrowdSec is enabled, the forbidden response is generated after its access
checks so the bouncer and AppSec can inspect the original method, URI, and body.
Bouncer denials take precedence over the decorative page. The error-page internal
redirect retains the standard internal-request exclusion to avoid double checks.
This does not enable CrowdSec or AppSec on deployments where they are disabled.
HTTP/TLS rejections and ACME challenge handling remain separate routes.

The page's own 403 response has a restrictive CSP and framing denial. If changing
its stylesheet, update the CSP hash in backend/templates/default.conf; the backend
regression test checks the match. Custom HTML does not inherit this policy.
