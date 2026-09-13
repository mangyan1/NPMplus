# Code guidelines — NPMplus security fork

These rules apply to every change in this repository. They are constraints, not
suggestions: violating one is a rejected change, not a style disagreement.
The rationale and history for each rule lives in `FORK.md`; this file is the
enforceable summary. When a rule and an upstream change conflict, the rule
wins and the upstream change needs explicit owner-approved redesign first.

## Security invariants (never break)

1. **Never expose subprocess output to API clients.** CommandError messages
   contain raw stdout/stderr of certbot and other tools, which include
   credentials, file paths, and hostnames. The central error handler returns
   `Internal Error` for them, with the request id only. Do not re-add
   `payload.error.output`, `payload.debug`, `err.previous`, or stack traces to
   any response, and do not mark CommandError public.
2. **401 is for rejected sessions, 403 for permission denials.** A dead or
   absent cookie must be 401 so the UI clears its state and shows login; an
   authenticated user without permission gets 403. Never merge these paths.
3. **The admin UI index and SPA fallback are `no-store`.** Content-hashed
   assets under `/assets/` may be immutable; everything that names them must
   not cache. A stale index breaks the app after every image build.
4. **Never cache anything that embeds per-request identity.** Validators,
   templates, or helpers that bake in a specific user's id, token, or
   object-id enum must not be shared across requests. The permission cache
   excludes the `users-*` permissions for exactly this reason; the pin is the
   `cached permission checks never leak one user's id` test in
   `backend/test/api.test.js`.
5. **Subprocess failure output stays server-side** even when the public
   message is generic; log it with the request id instead of returning it.
6. **Do not widen `lib/bounded-fetch.js` contracts.** External fetches keep
   their timeouts and byte caps. If a new fetch is added, it uses
   `fetchWithTimeout` plus a bounded read, not bare `fetch`.
7. **Do not remove a security regression test to make a change pass.** If a
   pin blocks work, the work is wrong or the pin needs a deliberate,
   owner-approved redesign with a replacement pin in the same change.
8. **Rate limits are security boundaries.** Login throttling (5 failures /
   5 minutes, failures count) and the per-route limits keep their semantics.
   "Optimization" may not bypass, widen, or skip them.
9. **CrowdSec, AppSec, Anubis, and the firewall bouncer are never disabled**
   to make a test, scan, or workflow pass. Findings get documented triage.

## Change discipline (how to work here)

- **Probe, don't infer.** A claim about a driver, dependency, or runtime
  enters the CHANGELOG only with a direct probe of the exact pinned build.
  An empty readback means "rejected by the API surface", not "feature
  absent" — find the real mechanism before writing it down.
- **Negative-verify new pins.** A test that has never failed proves nothing:
  sabotage the guard on purpose, watch the pin turn red, restore, watch green.
- **Characterization tests precede risky edits.** Before changing behavior in
  shared/auth code, pin the current contract first (see `FORK.md`).
- **One small PR per concern**, with the blast radius stated. Security-relevant
  changes name the files whose failure mode they touch.
- **Keep the blast radius small in shared files**: additive lines inside
  existing structures over rewrites; existing module paths over new trees.
- **Verify in the environment that runs it.** Windows working trees show
  CRLF format noise; biome CI runs on the Linux LF checkout. Driver claims
  are probed in a Linux container on the pinned version.

## The verification ladder (what "done" means)

A change is done when it has: backend tests green (`node --test test/*.test.js`
in `backend/`), schema validation (`node validate-schema.js`), lint as CI sees
it (per-package `biome ci`), and — for anything touching auth, permissions,
session handling, nginx config, the installer, or restore — the relevant
recovery/sync contracts on Linux plus a real-router or browser smoke. A
missing check is a blocker, not a pass by absence.