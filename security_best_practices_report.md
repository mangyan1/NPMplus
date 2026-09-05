# NPMplus security remediation report

## CVE remediation status — 2026-09-04

The repository-controlled recommendations from the point-in-time rescan have been implemented in the working tree:

| Finding | Status | Implemented control |
| --- | --- | --- |
| CVE-R01 — Caddy | Resolved in the fork image | Caddy 2.11.4 is rebuilt from stable source with Go 1.26.8, `x/crypto` 0.55.0, `x/net` 0.57.0, gRPC-Go 1.83.1, Caddy's reduced database build tags, and upgraded Alpine packages. The resulting Linux/AMD64 image has zero Trivy high/critical findings. |
| CVE-R02 — CrowdSec | Upstream-blocked; monitored and mitigated | The deployment remains SQLite-based with APIs bound to loopback. A daily scan follows `crowdsecurity/crowdsec:latest`; reviewed upstream findings have documented exceptions that expire on 2026-10-04. New high/critical findings fail CI. Protection remains enabled. |
| CVE-R03 — Anubis | Upstream-blocked; monitored and mitigated | The deployment remains per-host and loopback-only. CI resolves the latest stable Anubis release daily; reviewed upstream findings have documented exceptions that expire on 2026-10-04. New high/critical findings fail CI. Protection remains enabled. |
| CVE-R04 — Python packaging tools | Resolved in the fork image | Pip is used only to install pinned Certbot during the image build and is then removed. Runtime Certbot plugin downloads and the unsafe compatibility environment switch were removed; provider plugins must be baked into a reviewed custom image. |

Pull requests now scan the actual final Linux/AMD64 application image and changed Caddy image. A scheduled workflow scans all four published components, retains readable and SARIF reports, uploads SARIF to GitHub code scanning, and enforces the two separate expiring upstream baselines. SQLite remains the default; PostgreSQL and PHP-FPM were not added because neither is a CVE remediation for this deployment.

Validation performed for the remediation:

- A full Linux/AMD64 NPMplus production image build passed. Certbot 5.7.0, Nginx 1.31.5, and Node.js 24.18.1 ran in the result, while the pip command and package directory were absent.
- Trivy 0.74.0 reported zero high/critical findings for the rebuilt NPMplus and Caddy images.
- Caddy reported Go 1.26.8 and the intended module replacements, validated its configuration during the build, and returned the expected HTTP-to-HTTPS redirect in a container smoke test.
- The CrowdSec and Anubis enforcement scans passed with their separate reviewed baselines; the latest stable Anubis resolver selected v1.27.0.
- All 20 backend tests and the OpenAPI schema check passed. The frontend TypeScript and Vite production build passed as part of the final image build.
- Compose rendering, changed shell syntax, workflow YAML parsing, Dockerfile linting, and the complete GitHub Actions workflow set were checked. Actionlint reported only pre-existing informational ShellCheck findings in unrelated workflow scripts.

## Point-in-time CVE rescan — 2026-09-04

- Repository baseline: `develop` at `6ab79c8a2d607ba29e2e595382b170bfb135ccd3`
- Scan completed: 2026-09-04 America/Edmonton (2026-09-05 UTC)
- Scanner: Trivy 0.74.0, image digest `aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969`
- Scope: both pnpm lockfiles, repository filesystem, GitHub Dependabot/secret/code-scanning alerts, and the exact Linux/amd64 runtime image digests deployed by the installer.

### Executive result

Yes. The current container set contains published vulnerability matches. The JavaScript application dependencies are clean, but the optional Caddy, CrowdSec, and Anubis binaries were built before several recent Go security fixes.

Scanner counts are inventory signals, not proof that every CVE is exploitable. A single advisory can appear in multiple binaries or packages, and Go scanners report a module when the vulnerable package may not be reachable in the compiled program. The priorities below account for how this fork actually deploys each component.

| Target scanned | Exact image/index digest | All scanner occurrences | High/critical detail | Assessment |
| --- | --- | ---: | --- | --- |
| NPMplus application | `sha256:9d9fe40b804d1ddf59919318f29d418d4673940d1cc37cafd41002b43bc4cd2b` | 3 (3 unique IDs) | 2 high, 0 critical | Two Python packaging-tool matches; not exposed through the web application. See CVE-R04. |
| NPMplus Caddy | `sha256:2dcac425385b78408dbad163e32414e6a11795a8fb73c0e142abc17e489d7fa2` | 42 (31 unique IDs) | 18 fixable occurrences: 1 Trivy-critical and 17 high, representing 16 unique IDs | Highest remediation priority because Caddy is the public port-80 edge. See CVE-R01. |
| CrowdSec 1.8.1/latest | `sha256:0f2523fa61ef507f15d953045cface490cc880670c62f2755ced17524107f71a` | 66 (26 unique IDs) | 18 high occurrences: 16 fixable and 2 currently without a fixed version, representing 9 unique IDs | Upstream image issue; practical exposure is reduced by loopback binding and default SQLite use. See CVE-R02. |
| Anubis 1.27.0 | `sha256:8828275668b7bc675679f100970f9714f731388fbbf66ae94de8aca952e3fc4a` | 12 (12 unique IDs) | 11 high, 0 critical | Upstream image issue; loopback-only but indirectly handles untrusted requests through `auth_request`. See CVE-R03. |

The all-severity totals above include low, medium, unknown, duplicate, and no-fix matches. The detailed findings prioritize high/critical issues. A scan limited to fixable high/critical findings reported zero results for the repository filesystem itself.

### CVE-R01 — Public Caddy image contains stale Go and Alpine components

- Severity: **High operational priority**. Trivy labels one module match critical; GitHub's reviewed advisory labels that CVE high.
- Location: `caddy/Dockerfile:2`, `caddy/Dockerfile:4`, `.github/workflows/caddy.yml:1`
- Evidence: the image contains Alpine OpenSSL 3.5.7-r0, Go stdlib 1.26.3, `golang.org/x/net` 0.55.0, `golang.org/x/text` 0.37.0, `golang.org/x/crypto` 0.52.0, and gRPC-Go 1.81.0. Fixed releases are available for these components. The pinned official `caddy:2.11.4` image is still the current Caddy release and was built in June 2026, before the affected Go fixes.
- Unique high/critical IDs: `CVE-2026-14456`, `CVE-2026-27145`, `CVE-2026-33818`, `CVE-2026-39821`, `CVE-2026-39822`, `CVE-2026-42504`, `CVE-2026-46600`, `CVE-2026-56852`, `CVE-2026-56853`, `CVE-2026-56854`, `CVE-2026-56858`, `CVE-2026-56859`, `CVE-2026-56860`, `CVE-2026-56862`, `CVE-2026-84304`, and `GHSA-hrxh-6v49-42gf`.
- Impact: the stdlib, HTTP/2, TLS, DNS, URL, and template advisories can cause denial of service or unsafe parsing if the affected code path is present and reached by attacker-controlled traffic. Caddy is Internet-facing in this stack, so these cannot be dismissed solely because they are transitive dependencies.
- Reachability/false-positive note: `CVE-2026-56854` concerns SSH source-address authorization. This deployment does not configure an SSH server, so the scanner's critical rating is not evidence of a critical remote Caddy exploit. The gRPC xDS authorization portion of `GHSA-hrxh-6v49-42gf` is also not configured here, although the advisory's HTTP/2 resource-exhaustion path may still matter when server transport code is linked and reachable.
- Recommended fix: rebuild the Caddy image with a patched Alpine package set and a Caddy binary compiled with patched Go stdlib and module versions. As of this scan, Caddy 2.11.4 remains the latest stable release, so simply resolving the same tag again does not fix the binary. Prefer a reviewed patch build or the next stable Caddy release; do not silently track Caddy `master` in production.
- Temporary mitigation: keep normal connection/request limits in front of public services and omit the optional Caddy container if its port-80 redirect is not needed. HTTPS on the main NPMplus listener remains available; this is not a recommendation to disable CrowdSec or AppSec.

References: [Go release history](https://go.dev/doc/devel/release), [Caddy releases](https://github.com/caddyserver/caddy/releases), [CVE-2026-56854 / GHSA-gjhq-gjfw-99mq](https://github.com/advisories/GHSA-gjhq-gjfw-99mq), [gRPC GHSA-hrxh-6v49-42gf](https://github.com/advisories/GHSA-hrxh-6v49-42gf).

### CVE-R02 — Latest CrowdSec image contains vulnerable helper and Go binaries

- Severity: **Medium operational priority**, with upstream high-severity matches.
- Location: `setup-npmplus.sh:23`, `setup-npmplus.sh:1003`, `setup-npmplus.sh:1240`
- Evidence: CrowdSec 1.8.1/latest contains 18 high occurrences representing 9 unique IDs. The fixable matches are OpenSSL in the Alpine layer; `x/net` and `x/text` in the `yq` helper; and `CVE-2026-84304` in CrowdSec, `cscli`, and six notification plugin binaries. `CVE-2026-32286` appears in the CrowdSec and `cscli` PostgreSQL protocol dependency and currently has no fixed version reported.
- Unique high IDs: `CVE-2026-14456`, `CVE-2026-25681`, `CVE-2026-27136`, `CVE-2026-32286`, `CVE-2026-33814`, `CVE-2026-39821`, `CVE-2026-46600`, `CVE-2026-56852`, and `CVE-2026-84304`.
- Impact: `CVE-2026-84304` is a gRPC HTTP/2 DATA-frame memory-exhaustion issue. The remaining findings include parser/DoS issues in support tooling and the PostgreSQL protocol package.
- Reachability/false-positive note: the installer binds CrowdSec API/AppSec/metrics ports to loopback, `yq` is used as local tooling rather than a public web server, optional notification plugins are not enabled by this installer, and the standard generated deployment uses CrowdSec's local SQLite database rather than PostgreSQL. Those facts reduce exposure, but do not remove the need for an upstream rebuild.
- Recommended fix: consume a patched CrowdSec release/image when upstream publishes it and keep the immutable-digest update behavior. Repacking only the Alpine layer would fix OpenSSL but cannot repair Go dependencies compiled into CrowdSec, `cscli`, plugins, or `yq`.
- Temporary mitigation: retain the current loopback-only bindings and do not expose ports 6060, 7422, or 8080 to the LAN/Internet.

References: [CrowdSec releases](https://github.com/crowdsecurity/crowdsec/releases), [CVE-2026-84304 / GHSA-vp52-pcj8-j9qc](https://github.com/advisories/GHSA-vp52-pcj8-j9qc), [CVE-2026-32286 / GHSA-jqcq-xjh3-6g23](https://github.com/advisories/GHSA-jqcq-xjh3-6g23).

### CVE-R03 — Latest Anubis image predates recent Go security rebuilds

- Severity: **Medium operational priority**, with 11 high scanner matches.
- Location: `setup-npmplus.sh:349`, `setup-npmplus.sh:1017`, `setup-npmplus.sh:1264`
- Evidence: Anubis 1.27.0 contains Go stdlib 1.26.5, `x/text` 0.38.0, and gRPC-Go 1.81.1. Trivy reports 11 high and one medium fixable advisory. The high IDs are `CVE-2026-33818`, `CVE-2026-39821`, `CVE-2026-46600`, `CVE-2026-56852`, `CVE-2026-56853`, `CVE-2026-56858`, `CVE-2026-56859`, `CVE-2026-56860`, `CVE-2026-56862`, `CVE-2026-84304`, and `GHSA-hrxh-6v49-42gf`.
- Impact: the relevant classes are crafted-input CPU/memory exhaustion, HTTP/2 denial of service, URL/XML/template parsing problems, and gRPC authorization/transport issues if the matching paths are linked and exercised.
- Reachability/false-positive note: Anubis is bound to `127.0.0.1:8923`, but Nginx can send attacker-controlled request metadata to it via `auth_request`, so loopback binding is not by itself a complete reachability dismissal. The stack does not configure gRPC or xDS for Anubis, reducing the likelihood of the gRPC findings.
- Recommended fix: update to an upstream Anubis image rebuilt with Go 1.26.6 or newer and patched modules. Version 1.27.0 is still the latest stable release as of the scan; the installer already selects the latest validated release and immutable digest, so upstream must publish a rebuilt tag or new release.
- Temporary mitigation: continue enabling Anubis only per host, keep its listener loopback-only, and use normal proxy request/connection limits.

References: [Anubis releases](https://github.com/TecharoHQ/anubis/releases), [Go release history](https://go.dev/doc/devel/release), [CVE-2026-84304 / GHSA-vp52-pcj8-j9qc](https://github.com/advisories/GHSA-vp52-pcj8-j9qc).

### CVE-R04 — Main image Python findings are packaging-tool artifacts

- Severity: **Low practical risk** despite two high and one medium scanner labels.
- Location: `Dockerfile:267`, `Dockerfile:268`
- Evidence: Trivy reports `setuptools` 70.3.0 for `CVE-2025-47273` and `CVE-2026-59890`, plus `msgpack` 1.1.2 for `GHSA-6v7p-g79w-8964`. Runtime inspection shows no installed `setuptools` distribution and no installed standalone `msgpack` distribution. The matching MessagePack code is vendored inside pip 26.2.1 under `pip/_vendor/msgpack`.
- Impact: the setuptools path-traversal issue requires use of its package download machinery; that package is not installed. The MessagePack issue requires local pip code to reuse a malformed `Unpacker` after catching an error. Neither is reachable from an NPMplus HTTP request.
- False-positive note: the setuptools entries are stale/metadata scanner matches rather than an importable runtime package. The msgpack code exists, but only inside the administrative pip tool, so this is not a web application CVE.
- Recommended fix: remove pip/build tooling from the final runtime image when practical, or update the pip release after it vendors MessagePack 1.2.1. Keep custom Certbot provider plugins baked into reviewed images rather than installing them at runtime.

References: [setuptools CVE-2025-47273](https://github.com/advisories/GHSA-5rjg-fvgr-3xxf), [MessagePack GHSA-6v7p-g79w-8964](https://github.com/advisories/GHSA-6v7p-g79w-8964).

### Dependency and GitHub alert checks

- Backend `pnpm audit`, production and full dependency graph: 0 advisories.
- Frontend `pnpm audit`, production and full dependency graph: 0 advisories.
- GitHub Dependabot open alerts: 0.
- GitHub secret-scanning open alerts: 0.
- Repository filesystem, fixable high/critical dependency scan: 0 findings.
- GitHub CodeQL open alerts: 5. These are not CVEs and were manually triaged as false positives:
  - `backend/routes/crowdsec.js:188` hashes a high-entropy machine password only to key an in-memory token cache; it is not a password verifier or stored credential hash.
  - `backend/routes/oidc.js:188` and `backend/routes/oidc.js:201` set short-lived bearer tokens in signed, `Secure`, `HttpOnly`, `SameSite=Strict`, `__Host-` cookies. The token must be recoverable by the server/client authentication flow; it is not written to persistent cleartext storage.
  - `backend/routes/nginx/certificates.js:231` and `backend/routes/nginx/certificates.js:345` read a numeric certificate ID from the URL path, not a password, token, or sensitive query value.

No GitHub alert was dismissed or otherwise changed during this review.

### Control gap and recommended order

At the scan baseline, the repository had dependency update automation but no scheduled container vulnerability scan. Because release tags and image digests can remain unchanged while new CVEs are published, build-on-change alone did not detect these August/September advisories. The remediation status above records the controls added after this observation.

Original recommended remediation order (now implemented where repository-controlled):

1. Add a scheduled and pull-request Trivy gate that scans the actual Linux/amd64 final images, publishes a human-readable artifact/SARIF result, and fails only on reviewed high/critical findings with a documented, expiring ignore process.
2. Produce or adopt a patched Caddy binary/image; rebuild the Caddy Alpine layer immediately for the OpenSSL fix.
3. Track patched CrowdSec and Anubis upstream images, then refresh their immutable digests through the existing safe-update path.
4. Remove unnecessary Python packaging tools from the NPMplus runtime image.

This is a static dependency/container assessment, not a live penetration test. It does not prove exploitability or confirm the patch state of a VM that is not running these exact digests.

> Historical note: the remediation record below describes the 2026-09-02 source review. Its statement that no reviewed production finding remained open was correct for that assessment; the CVE rescan above incorporates vulnerabilities published or recognized afterward.

- Assessment and remediation date: 2026-09-02
- Repository: `mangyan1/NPMplus`
- Branch baseline: `develop` at `4c1e778149f8b3def4cbb20c1c6ef4419d1193a4`
- Scope: Express backend, React frontend, Nginx templates, Docker build/runtime configuration, host setup and diagnostic scripts, dependency policy, and GitHub Actions.

## Result

All 12 findings from the security review have been addressed in the working tree. No known production finding remains open. Two changes require operator awareness:

- Existing installations keep their current host-network/root-compatible Compose layout during `--update`; the safer bridge-network and UID/GID 1000 defaults apply automatically to newly generated stacks. This avoids silently breaking existing proxy targets or data ownership. Existing operators can migrate during a maintenance window.
- Missing Certbot DNS plugins are not installed into the live container. Required provider plugins must be pinned in a reviewed custom image; the former runtime compatibility escape hatch was removed during the 2026-09-04 CVE remediation.

## Remediation summary

| ID | Original severity | Status | Remediation |
| --- | --- | --- | --- |
| SEC-001 | Critical | Resolved | First-user creation now requires a generated 256-bit, one-time setup token, compares it in constant time, serializes setup creation, removes the token after success, and keeps the admin port loopback-only by default. |
| SEC-002 | High | Resolved | Raw Nginx fields, local filesystem targets, and syntax-bearing custom paths are administrator-only at the backend boundary. New non-admins receive view-only defaults, and host/domain input validation is stricter. |
| SEC-003 | High | Resolved | Verified email checks fail closed. UserInfo is fetched when verification is missing, and OIDC identities are persistently bound to a unique hash of issuer plus subject rather than authorized by email on every login. |
| SEC-004 | High | Resolved | Upstream synchronization now pushes to an automation branch and opens a pull request. Pull-request builds are read-only and cannot publish images; mutable formatter/tool execution was removed or digest/version pinned. Release tags are validated and passed to shells through quoted environment variables. |
| SEC-005 | High | Resolved | Runtime Certbot plugin installation is unavailable. Certbot and LuaRocks build dependencies are version-pinned, pip is removed from the final image, and provider plugins must be baked into a reviewed custom image. |
| SEC-006 | Medium | Resolved | API errors no longer return stack traces or nested command failures. Clients receive a correlation ID while full diagnostics stay in server logs. JSON, form, avatar, and certificate-upload bodies are explicitly bounded. |
| SEC-007 | Medium | Resolved | External requests use abort timeouts and bounded streaming readers. Cloudflare range refresh no longer blocks the backend listener during startup. |
| SEC-008 | Medium | Resolved for defaults | The sample and fresh installer use a bridge network, explicit ports, loopback-only administration, UID/GID 1000, minimal required capabilities, and `no-new-privileges`. Host networking is opt-in. |
| SEC-009 | Medium | Resolved | Secret-file support was added for cookie, OIDC, bootstrap, ACME, and database secrets. The entrypoint resolves and unsets `_FILE` pointers before later validation; Compose examples use mounted secret files. |
| SEC-010 | Medium | Resolved | Password reset accepts only stdin, and CrowdSec HTTP credentials/bodies are supplied through curl stdin configuration instead of process arguments. |
| SEC-011 | Low | Resolved | Unknown/default HTTP hosts are rejected with 400/444 rather than redirected using the untrusted Host header. |
| SEC-012 | Low | Resolved | pnpm uses a seven-day release quarantine with narrow reviewed exceptions; pip, Certbot, LuaRocks, pnpm, and formatter images/tools are pinned. |

## Key implementation details

### Setup and identity

- `backend/setup.js` owns setup-token creation, validation, and deletion.
- `backend/routes/users.js` enforces the token on unauthenticated first-user creation and prevents concurrent first-user requests in the application process.
- `frontend/src/pages/Setup/index.tsx` prompts for the setup token and sends it only in the dedicated request header.
- `backend/internal/token.js`, `backend/models/auth.js`, and migration `20260902210000_oidc_identity_unique.js` implement stable OIDC identity binding.

### Authorization and input boundaries

- `backend/lib/nginx-privilege.js` compares the existing and proposed privileged configuration so delegated users may update ordinary settings without gaining raw Nginx or filesystem access.
- Proxy, redirect, dead-host, and stream create/update paths call this guard server-side.
- Domain, forward-host, and stream-host schemas reject whitespace and Nginx metacharacters and impose practical length limits.

### Runtime and supply chain

- `backend/lib/bounded-fetch.js` centralizes timed, size-bounded outbound reads.
- `rootfs/usr/local/bin/envs.sh` loads supported Docker/Kubernetes secret files and rejects ambiguous value-plus-file configuration.
- `compose.yaml` and `setup-npmplus.sh` provide safer fresh-deployment defaults.
- GitHub Actions use least-privilege permissions, reviewable upstream pull requests, non-publishing PR builds, and pinned tooling.

## Validation

The final verification completed successfully:

- Backend: 10/10 unit and security tests passed, including response-size limits, response-body timeout behavior, delegated Nginx-field enforcement, and fork update checks.
- Frontend: TypeScript project checking and the Vite production build passed.
- Supply chain: both production `pnpm audit` runs reported no known vulnerabilities, and both frozen-lockfile installs satisfy the seven-day release policy.
- Configuration: the OpenAPI schema, backend JSON schemas, all workflow YAML, Compose rendering, and Bash/POSIX shell syntax passed.
- Container image: a complete production Docker build passed, including the Nginx/AWS-LC compile and frontend build stages; the resulting image successfully ran its pinned Certbot, Nginx, Node.js, and pip executables.
- Migration: the OIDC uniqueness migration was exercised up/down against SQLite and rejected a duplicate identity as intended.
- Static analysis: Semgrep scanned tracked and newly created files. The secret scan reported zero findings. The JavaScript/TypeScript/OWASP scan found no actionable application or workflow issue after remediation; its remaining 16 alerts are the same generic Nginx `$host` rule in configured virtual-host redirects, upstream headers, TLS names, mapping, and logging. The default/unknown host now rejects requests, and configured domain inputs are constrained, so those occurrences were reviewed as non-actionable rather than suppressed.
- Repository hygiene: `git diff --check` passed.

## Residual operational guidance

- Keep port 81 bound to host loopback and administer through an SSH tunnel.
- Treat Docker access as root-equivalent even when application services drop privileges.
- Bake required Certbot DNS plugins into a reviewed image before the next request or renewal for an installation that uses DNS challenges.
- Review and merge the upstream-sync pull request only after CI and code review.
- Protect older backups made before setup script v1.16 because they may contain legacy inline bootstrap credentials.

This was a repository source/configuration review, not a live penetration test of a VM, registry, OIDC provider, firewall, or GitHub organization settings.
