# NPMplus Security Fork — maintained by mangyan1

NPMplus gives you a web dashboard for publishing services securely through Nginx. This security-focused fork is maintained by [mangyan1](https://github.com/mangyan1) and adds a guided server installer, CrowdSec protection, automatic backups, safe updates with rollback, and additional security fixes.

It is based on [ZoeyVid/NPMplus](https://github.com/ZoeyVid/NPMplus) and the original [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager). [Project website](https://mangyan1.github.io/NPMplus/)

![The NPMplus security overview showing CrowdSec and Anubis status, local bans, attack mix, WAF verdicts, and a geographic attack map](docs/security-overview.webp)

[Install](#install) · [Open the dashboard](#open-the-dashboard) · [Maintenance](#maintenance) · [What this fork adds](#what-this-fork-adds) · [Guides and help](#get-help)

## Install

You need a Debian 12/13 or Ubuntu 22.04+ server with an AMD64-v2 or ARM64 CPU, an account that can run `sudo`, and ports `80/tcp`, `443/tcp`, `443/udp` free for your websites. The installer can install Docker if it is missing, and it asks before making important changes.

The recommended installer is the pinned **v2.15.1-mangyan1.rc.8** release candidate: SHA-256-verified, and it resolves its images to immutable digests. The maintained [develop branch](https://github.com/mangyan1/NPMplus/tree/develop) carries newer fixes between releases, for rolling test deployments.

Copy this entire command, paste it into a **test server** terminal, and press Enter:

```bash
wget -qO setup-npmplus.sh https://github.com/mangyan1/NPMplus/releases/download/v2.15.1-mangyan1.rc.8/setup-npmplus.sh &&
wget -qO setup-npmplus.sh.sha256 https://github.com/mangyan1/NPMplus/releases/download/v2.15.1-mangyan1.rc.8/setup-npmplus.sh.sha256 &&
sha256sum -c setup-npmplus.sh.sha256 &&
sudo bash setup-npmplus.sh
```

Review the script before running it on a production host. Select **Install NPMplus**, then answer the questions; if you are unsure, press Enter to accept the displayed default. The recommended defaults enable CrowdSec, CrowdSec AppSec, the firewall bouncer, and Anubis. Anubis's global catch-all challenge defaults off so APIs, licensing servers, webhooks, monitors, and other non-browser clients keep working, and AppSec can be turned off per proxy host if an application has a confirmed compatibility problem.

For the easiest first login, provide an administrator email and password when the installer asks. The password is handled as a temporary secret and is not saved in `compose.yaml`.

Do not run this over an existing manual Nginx Proxy Manager deployment. Read the [compatibility and migration notes](ADVANCED.md#compatibility-to-upstream) and take a backup first; migrating back to the original project is not supported.

## Open the dashboard

The dashboard is HTTPS on port 81 and is published on the server's loopback interface only, so it is not reachable from the internet. On the server itself it is at <https://localhost:81>. From your own computer:

```bash
ssh -L 8181:127.0.0.1:81 YOUR_USER@YOUR_SERVER_IP
```

`127.0.0.1` is where port 81 listens on the server (do not use `localhost` here: the published port is IPv4-only, so a name that resolves to IPv6 fails) and `8181` is the local port on your computer. Leave that terminal open and visit <https://localhost:8181>. A certificate warning is expected - the dashboard certificate is self-signed.

If you allowed private-LAN dashboard access, the installer prints the VM's private address and the permitted subnet; visit `https://VM_LAN_IP:81` from that LAN. Never forward port 81 on your router.

If you did not provide an administrator email and password during installation, read the one-time setup token on the server and enter it in the setup page:

```bash
sudo docker exec npmplus cat /data/npmplus/setup-token
```

## Maintenance

One short command opens the menu for safe updates, CrowdSec checks, reboot diagnostics, restore, reconfiguration, and uninstalling:

```bash
sudo /opt/npmplus/setup-npmplus.sh
```

- **Safe update** - snapshot, new images, full health checks, automatic rollback on failure.
- **Check or repair CrowdSec** - tests containers, API, credentials, and registration; repairs rejected keys.
- **Startup/reboot diagnostic report** - read-only service, network, Docker, and container details to a private `/tmp` report.
- **Reconfigure installation** - reruns the advanced installation questions.
- **Create a backup now** - a fresh archive immediately, using the same helper as the daily cron.
- **Restore a backup from an archive** - put old data back onto this machine.
- **Uninstall** - final backup, clear description, typed confirmation.

Backups are stored under `/var/backups/npmplus` (seven kept); the update snapshot under `/var/backups/npmplus-last-good`. Check the stack with:

```bash
sudo docker compose -f /opt/npmplus/compose.yaml ps
```

Every service should say `Up`, and `npmplus` should become `healthy` after startup. To move to a newer release, use the installer and checksum on that release's page.

Moving to another machine, reading logs, recovering a failed update, and the advanced opt-ins an ordinary update deliberately preserves (AppSec, protected startup, the Cloudflare origin lock) are all covered in [host setup and operations](docs/setup-npmplus.md) - migration is three commands, and [Diagnostics](docs/setup-npmplus.md#diagnostics) covers logs, CrowdSec checks, and backup restoration.

## What this fork adds

- One interactive installer for installation, updates, diagnostics, restore, and uninstall, with loopback-only dashboard access by default.
- CrowdSec, AppSec WAF, and firewall-bouncer protection that fails closed, with per-host AppSec switches and protected startup keeping public ports closed until CrowdSec enforcement and service health are proven.
- Optional Cloudflare-only origin filtering, Anubis bot protection and honeypot bans, Caddy redirects, and a recommended UFW set: 443/tcp+udp public, SSH and the admin UI restricted to the private LAN.
- Safe monthly updates with automatic rollback, daily backups, and CrowdSec credential healing, plus hardened auxiliary containers (read-only root filesystems, dropped capabilities, `no-new-privileges`) and daily container CVE monitoring.
- Proxy hosts, redirects, streams, access lists, certificates from Let's Encrypt or another ACME authority, HTTP/3, modern TLS, mTLS, OIDC, `auth_request`, and load balancing.
- A CrowdSec and Anubis security dashboard with a paginated **Attackers** view, AppSec WAF monitoring, per-host attack evidence, local bans with exact-decision unban, and audit logging. See [investigating observed attackers](docs/attacker-investigation.md) and [attack evidence and limits](docs/security-telemetry.md#attack-evidence-details).
- Security headers, strict browser policy, protected session cookies, server-side logout revocation, Argon2id password hashing, rate limits, and single-use login challenges.

See [Changes in this fork](ADVANCED.md#changes-in-this-fork-vs-zoeyvidnpmplus) for the detailed security and feature list, and [Advanced and manual configuration](ADVANCED.md) for custom Nginx directives - guides written for other Nginx Proxy Manager versions may not match NPMplus.

## Releases and security reports

Release tags build AMD64 and ARM64 images in this repository, attach build provenance and an SBOM, and scan the exact images before publishing to GitHub Container Registry. Publication also resolves and scans the exact Caddy, CrowdSec, and Anubis images selected by the installer. A release candidate updates only the `rc` channel; only a final release can update `latest`.

Each GitHub release includes a version-pinned `setup-npmplus.sh` and its SHA-256 checksum, and the final image and installer files also receive GitHub identity-backed artifact attestations. Verify a downloaded asset with `gh attestation verify setup-npmplus.sh --repo mangyan1/NPMplus`, or an image with `gh attestation verify oci://ghcr.io/mangyan1/npmplus:<tag> --repo mangyan1/NPMplus`. Release candidates are for test systems first. Report suspected vulnerabilities privately by following [the security policy](SECURITY.md), not through a public issue.

## Get help

- [Questions and discussions](https://github.com/ZoeyVid/NPMplus/discussions)
- [Report a problem in this fork](https://github.com/mangyan1/NPMplus/issues)
- [NPMplus Discord](https://discord.gg/y8DhYhv427)
- [Fork maintenance guide](FORK.md) for maintainers merging ZoeyVid updates

Please report fork-specific problems here before opening an upstream issue. When requesting help, share command output with public IP addresses, domains, email addresses, and secrets removed first.

## License and attribution

This fork is distributed under the GNU Affero General Public License version 3 or later. It is based on the MIT-licensed Nginx Proxy Manager. By using NPMplus, you agree to the terms of Let's Encrypt or your selected certificate authority.

NPMplus is maintained by ZoeyVid. This fork is maintained by [mangyan1](https://github.com/mangyan1) and retains attribution to the original Nginx Proxy Manager creator and upstream contributors.
