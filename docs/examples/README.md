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
