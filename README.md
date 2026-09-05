# NPMplus Security Fork — maintained by mangyan1

NPMplus gives you a web dashboard for publishing services securely through Nginx. This security-focused fork is maintained by [mangyan1](https://github.com/mangyan1) and adds a guided server installer, CrowdSec protection, automatic backups, safe updates with rollback, and additional security fixes.

It is based on [ZoeyVid/NPMplus](https://github.com/ZoeyVid/NPMplus) and the original [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager).

[Project website](https://mangyan1.github.io/NPMplus/) · [Install NPMplus](#new-installation) · [See the main features](#main-features)

## Before you start

You need:

- A Debian 12/13 or Ubuntu 22.04+ server.
- A user account that can run `sudo`.
- An AMD64-v2 or ARM64 server.
- Ports `80/tcp`, `443/tcp`, and `443/udp` available for your websites.
- A domain pointed to your server when you are ready to publish a website.

The installer can install Docker if it is missing. It asks before making important changes.

## New installation

Copy this entire command, paste it into the server terminal, and press Enter:

```bash
wget -qO setup-npmplus.sh https://raw.githubusercontent.com/mangyan1/NPMplus/develop/setup-npmplus.sh &&
sudo bash setup-npmplus.sh
```

Answer the questions shown by the installer. If you are unsure, press Enter to accept the displayed default. The recommended defaults enable CrowdSec, CrowdSec AppSec web-application protection, the firewall bouncer, and Anubis. AppSec can still be turned off for an individual proxy host if an application has a confirmed compatibility problem.

For the easiest first login, provide an administrator email and password when the installer asks. The password is handled as a temporary secret and is not saved in `compose.yaml`.

## Open the dashboard

The dashboard uses HTTPS on port 81. New installations publish this port only on the server's loopback interface (`127.0.0.1:81`), so it is not reachable directly from the internet.

On the server itself, the dashboard is at:

<https://localhost:81>

From your own computer, open a terminal and run:

```bash
ssh -L 8181:127.0.0.1:81 YOUR_USER@YOUR_SERVER_IP
```

`127.0.0.1` is where port 81 listens on the server (do not use `localhost` here: the published port is IPv4-only, so a name that resolves to IPv6 fails). `8181` is the local port on your computer. Leave that terminal open and visit:

<https://localhost:8181>

Your browser may show a certificate warning because the local dashboard certificate is self-signed.

If you answered `y` when the installer asked to open the admin port to the internet, skip the tunnel and visit `https://YOUR_SERVER_IP:81` directly.

If you did not provide an administrator email and password during installation, get the one-time setup token from the server:

```bash
sudo docker exec npmplus cat /data/npmplus/setup-token
```

Enter that token in the setup page. It is removed after the first administrator is created.

## Update NPMplus

Copy and paste this single command on the server:

```bash
wget -qO setup-npmplus.sh https://raw.githubusercontent.com/mangyan1/NPMplus/develop/setup-npmplus.sh &&
sudo bash setup-npmplus.sh --update
```

The updater creates a snapshot, installs the new images, checks the complete stack, and automatically restores the previous working version if the update fails.

An ordinary update keeps your existing AppSec choice. To enable AppSec on an existing installer-managed server, use this one-time command instead:

```bash
wget -qO setup-npmplus.sh https://raw.githubusercontent.com/mangyan1/NPMplus/develop/setup-npmplus.sh &&
sudo bash setup-npmplus.sh --update --enable-appsec
```

## Check that it is running

```bash
sudo docker compose -f /opt/npmplus/compose.yaml ps
```

Every listed service should say `Up`. The `npmplus` service should become `healthy` after startup.

The installer enables Docker and configures the containers to return automatically after a server restart.

## What the installer handles

- NPMplus and its web dashboard.
- Recommended CrowdSec, AppSec WAF, and firewall-bouncer protection, with AppSec compatibility exceptions per proxy host.
- Optional Anubis bot protection and honeypot bans.
- Optional Caddy HTTP-to-HTTPS redirect service.
- Safe monthly updates with automatic rollback.
- Daily backups with the latest seven archives retained.
- CrowdSec credential checks and automatic repair.
- Optional UFW firewall and unattended operating-system security updates.
- Loopback-only dashboard access and non-root services by default.

Backups are stored under `/var/backups/npmplus`. The latest update snapshot is stored under `/var/backups/npmplus-last-good`.

## If something goes wrong

Show recent logs:

```bash
sudo docker compose -f /opt/npmplus/compose.yaml logs --tail=200
```

If an update refuses to start, it usually means a service is already stopped or unhealthy. The updater does this to avoid creating a bad rollback snapshot.

For recovery, backup restoration, uninstalling, and reboot diagnostics, see the [setup and operations guide](docs/setup-npmplus.md).

When requesting help, share the command output but remove public IP addresses, domains, email addresses, and secrets first.

## Main features

- Proxy hosts, redirects, streams, access lists, certificates, and a modern admin dashboard.
- HTTP/3, modern TLS, mTLS, OIDC, `auth_request`, load balancing, and multiple access lists.
- Integrated CrowdSec and Anubis security dashboard with a compact overview, clickable KPI details, a lightweight animated geographic attack map, accessible activity charts, explicit CrowdSec/Anubis/honeypot status, paginated local alert and ban views, engine metrics, optional browser alerts while the page is open, manual bans, exact-decision unban, and audit logging. The map renders at most 12 aggregated origins with inline SVG and CSS—no WebGL, map-tile downloads, or browser-side IP lookup. CrowdSec community blocklists remain fully enforced but are summarized as metrics instead of flooding the page with remote IP entries.
- Dedicated AppSec WAF monitoring shows whether protection is configured, inspected/passed/blocked request totals, block rate, and the active compatibility policy.
- Security headers, strict browser policy, protected session cookies, rate limits, and safer defaults.
- Support for Let's Encrypt and other ACME certificate authorities.
- Optional GoAccess statistics and API documentation in the dashboard.

See [Changes in this fork](ADVANCED.md#changes-in-this-fork-vs-zoeyvidnpmplus) for the detailed security and feature list.

## Existing NPMplus or Nginx Proxy Manager installation

Do not run the new-install command over an existing manual deployment. Read the [compatibility and migration notes](ADVANCED.md#compatibility-to-upstream) and make a backup first. Migrating back to the original project is not supported.

## Advanced configuration

Most users do not need manual Compose editing or custom Nginx configuration.

This fork is intentionally focused on reverse proxying and security. It does not automate PHP-FPM deployment: application stacks should own their PHP runtime, files, updates, and health checks. The legacy inbuilt and external PHP-FPM instructions remain advanced compatibility guidance only.

- [Host setup, updates, backups, recovery, and diagnostics](docs/setup-npmplus.md)
- [Advanced and manual configuration reference](ADVANCED.md)
- [Example Compose file](compose.yaml)

Guides written for other Nginx Proxy Manager versions may not match NPMplus. Ask before adding custom Nginx directives that duplicate built-in features.

## Get help

- [Questions and discussions](https://github.com/ZoeyVid/NPMplus/discussions)
- [Report a problem in this fork](https://github.com/mangyan1/NPMplus/issues)
- [NPMplus Discord](https://discord.gg/y8DhYhv427)

Please report fork-specific problems here before opening an upstream issue.

## License and attribution

This fork is distributed under the GNU Affero General Public License version 3 or later. It is based on the MIT-licensed Nginx Proxy Manager. By using NPMplus, you agree to the terms of Let's Encrypt or your selected certificate authority.

NPMplus is maintained by ZoeyVid. This fork is maintained by [mangyan1](https://github.com/mangyan1) and retains attribution to the original Nginx Proxy Manager creator and upstream contributors.
