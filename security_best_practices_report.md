# NPMplus security remediation report

- Assessment and remediation date: 2026-09-02
- Repository: `mangyan1/NPMplus`
- Branch baseline: `develop` at `4c1e778149f8b3def4cbb20c1c6ef4419d1193a4`
- Scope: Express backend, React frontend, Nginx templates, Docker build/runtime configuration, host setup and diagnostic scripts, dependency policy, and GitHub Actions.

## Result

All 12 findings from the security review have been addressed in the working tree. No known production finding remains open. Two changes require operator awareness:

- Existing installations keep their current host-network/root-compatible Compose layout during `--update`; the safer bridge-network and UID/GID 1000 defaults apply automatically to newly generated stacks. This avoids silently breaking existing proxy targets or data ownership. Existing operators can migrate during a maintenance window.
- Missing Certbot DNS plugins are no longer installed into the live container by default. Required provider plugins should be pinned in a custom image. `ALLOW_RUNTIME_CERTBOT_PLUGIN_INSTALL=true` is retained only as an explicitly unsafe compatibility escape hatch.

## Remediation summary

| ID | Original severity | Status | Remediation |
| --- | --- | --- | --- |
| SEC-001 | Critical | Resolved | First-user creation now requires a generated 256-bit, one-time setup token, compares it in constant time, serializes setup creation, removes the token after success, and keeps the admin port loopback-only by default. |
| SEC-002 | High | Resolved | Raw Nginx fields, local filesystem targets, and syntax-bearing custom paths are administrator-only at the backend boundary. New non-admins receive view-only defaults, and host/domain input validation is stricter. |
| SEC-003 | High | Resolved | Verified email checks fail closed. UserInfo is fetched when verification is missing, and OIDC identities are persistently bound to a unique hash of issuer plus subject rather than authorized by email on every login. |
| SEC-004 | High | Resolved | Upstream synchronization now pushes to an automation branch and opens a pull request. Pull-request builds are read-only and cannot publish images; mutable formatter/tool execution was removed or digest/version pinned. Release tags are validated and passed to shells through quoted environment variables. |
| SEC-005 | High | Resolved | Runtime Certbot plugin installation is denied by default. Pip, Certbot, and LuaRocks build dependencies are version-pinned; the legacy runtime path requires explicit opt-in. |
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
