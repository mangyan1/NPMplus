# NPMplus host setup and operations

`setup-npmplus.sh` installs and operates this fork on a Debian or Ubuntu host. Run it as root, normally through `sudo`. It manages files under `/opt/npmplus`, optional CrowdSec and Anubis state, and only the host helpers described below.

## Fresh installation

Download the script from this fork, review it, and run it:

```bash
wget -O setup-npmplus.sh https://raw.githubusercontent.com/mangyan1/NPMplus/develop/setup-npmplus.sh
less setup-npmplus.sh
sudo bash setup-npmplus.sh
```

The interactive prompts cover the initial administrator, CrowdSec and AppSec, the firewall bouncer, Anubis, Caddy, Cloudflare trust, UFW, and unattended security upgrades. Existing UFW rules are preserved unless a reset is explicitly approved. Before a reset, the script detects the active SSH port and asks for confirmation so it does not assume port 22.

The generated Compose file is `/opt/npmplus/compose.yaml`. Registry channels are pulled and resolved to immutable `sha256` image digests before that file is written. An explicitly supplied initial administrator password is passed through a root-only, one-time Docker secret under `/run`, never embedded in Compose. After the API confirms that the account exists, the script truncates and removes the secret and removes its Compose references. Setup script v1.16 also scrubs legacy inline `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD` entries before an update snapshot is created.

Fresh v1.18 installations use a Compose bridge network, publish the admin listener on host loopback only, and run NPMplus services under UID/GID 1000 after privileged startup. Choose host networking only when an existing proxy target depends on host `127.0.0.1`; with bridge networking, use `host.docker.internal` for a service running directly on the Docker host. Port 81 should remain loopback-only and be reached through an SSH tunnel when remote administration is needed.

If you leave the initial administrator email and password empty, the browser setup wizard is protected by a generated 256-bit one-time token. Retrieve it locally after startup:

```bash
sudo docker exec npmplus cat /data/npmplus/setup-token
```

Enter that token in the setup form. The token file is mode `0600` and is removed after the first administrator account is created.

The script installs these root-owned helpers:

- `/usr/local/bin/npmplus-safe-update`: transactional monthly update.
- `/usr/local/bin/npmplus-backup`: daily data backup, retaining seven archives.
- `/usr/local/bin/npmplus-crowdsec-heal`: daily validation and repair of CrowdSec credentials.
- `/usr/local/bin/anubis-honeypot-ban`: optional five-minute Anubis-to-CrowdSec bridge.

## GitHub and download integrity

At startup, the local script compares its version and content with `mangyan1/NPMplus` on the `develop` branch. A newer remote script, or different content carrying the same version, blocks `--update`. The remote script is inspected but is never executed by that check.

`NPMPLUS_ALLOW_STALE_SCRIPT=true` bypasses the block for an intentional emergency update. Review the difference first; this override accepts older host-management logic.

The Docker and CrowdSec PackageCloud bootstrap scripts are downloaded to temporary files and checked against the SHA-256 values embedded in `setup-npmplus.sh` before execution. If either publisher changes its installer, maintainers must review the new file and deliberately update the corresponding hash.

## Updating

Download and review the current script before a manual update:

```bash
wget -O setup-npmplus.sh https://raw.githubusercontent.com/mangyan1/NPMplus/develop/setup-npmplus.sh
less setup-npmplus.sh
sudo bash setup-npmplus.sh --update
```

Manual and scheduled updates use the same maintenance lock and safe-update wrapper. The update refuses to use an unhealthy or incomplete running stack as its rollback baseline. It then:

1. Saves the Compose file, exact running image IDs, setup/helper scripts, and cron definitions.
2. Creates an online SQLite backup before a new application image can perform migrations.
3. Briefly stops CrowdSec and Anubis while copying their database-backed state, then restarts them. An exit trap attempts to restart a service if this snapshot is interrupted.
4. Resolves the configured image channels to immutable digests, refreshes optional Anubis policy and CrowdSec credentials, and redeploys. A transient Docker port-release failure during container replacement is retried once before rollback.
5. Checks every configured container, Docker health status, both NPMplus API listeners, and CrowdSec LAPI credentials.
6. Restores the saved application database, security-service state, host helpers, Compose file, and exact image IDs if the checks fail twice.

When upgrading an installation made by setup script v1.4 or earlier, v1.6 and later automatically replace the legacy updater before delegation and repair the installed setup script's execute permission. This avoids the legacy `/opt/npmplus/setup-npmplus.sh: Permission denied` failure and wrapper recursion.

Setup script v1.7 and later also repair the ownership of the persistent Anubis data directory before the safe-update preflight. Anubis runs as a non-root user; older root-owned `/opt/anubis-data` directories could make its bbolt database unwritable and leave `npmplus-anubis` restarting after installation or reboot.

Setup script v1.9 corrects the strict update probes: port 443 is checked as the public frontend listener, while the pretty-printed JSON API health response is checked on the admin listener at port 81.

Setup script v1.10 bumps the generated safe-update wrapper to version 3, ensuring installations with the older version-2 health probes replace that wrapper before the preflight runs.

Setup script v1.11 retries Compose deployment once when Docker has not yet released a published port from the container being replaced. Persistent port conflicts still trigger the normal automatic rollback.

Setup script v1.12 updates image references within their specific Compose service and retains the source tag alongside each immutable digest. This prevents the `develop` application and `caddy` images, which share one container repository, from being confused during an update.

Setup script v1.13 discovers the latest Anubis release through GitHub's public release redirect instead of the rate-limited anonymous REST API. An exhausted API quota can therefore no longer abort an otherwise healthy safe update.

Setup script v1.14 installs a Docker `ExecStartPre` resolver-file gate for hosts where `network-online.target` becomes active before DHCP or resolvconf publishes a nameserver.

Setup script v1.15 recognizes and safely recreates an NPMplus container whose Docker-managed resolver file is empty while the host resolver is populated. This repairs an existing `no name servers defined` boot failure before the transactional update takes its rollback baseline.

Setup script v1.16 removes one-time administrator bootstrap credentials from generated Compose files. Existing inline credentials are scrubbed at the beginning of the next update; new installations use a temporary Docker secret that is erased as soon as account creation is confirmed.

Setup script v1.18 keeps fresh-install defaults on bridge networking, loopback-only administration, and UID/GID 1000. It also protects browser-based initial setup with a one-time token. `--update` deliberately preserves an existing installation's network layout and UID/GID to avoid silently breaking proxy targets or filesystem ownership; recreate or edit the stack during a maintenance window if you want to adopt those isolation changes.

The rollback snapshot is stored root-only in `/var/backups/npmplus-last-good`. It is replaced by the next update and is not a substitute for the daily archives.

Backup archives created before upgrading to v1.16 can still contain an older Compose file with the initial password. Keep those archives mode `0600`; if one was copied or disclosed, change the administrator password in the UI and remove the exposed copy.

## Security dashboard

Open **CrowdSec** in the NPMplus navigation to see the combined CrowdSec and Anubis security dashboard. Its four tabs separate the daily operator view from deeper details:

- **Overview** shows attack activity, local bans, community protection, and honeypot bans as clickable summary cards. Its geographic map animates the latest observed attack origins; the pulses are a visual sequence, not inferred network routes.
- **Attack activity** shows alerts observed by this instance, with search, filters, sanitized event details, and one-click manual-ban prefilling.
- **Active bans** lists only local detections, manual bans, and imported local decisions. It loads 25 rows at a time and provides audited unban actions.
- **System** contains AppSec, parser, bouncer, machine, and LAPI performance metrics.

CrowdSec CAPI and blocklist decisions remain downloaded and enforced by the configured remediation components. The dashboard summarizes them as a community-protection count instead of loading the large remote IP list. It intentionally does not offer ordinary unban actions for those remote entries because CrowdSec can download them again. Clicking the community card shows the aggregate origin counts without exposing the individual addresses.

The header reports CrowdSec availability, Anubis reachability, and honeypot-log readiness separately. Honeypot readiness means the Anubis trap log is readable; it does not claim that an attacker has already been caught. The honeypot KPI reports active bans created from those catches, and its detail modal shows recent captured addresses. If CrowdSec decision counts are temporarily unavailable, the Anubis and honeypot checks still report independently.

The activity chart includes readable time labels and a screen-reader summary. Dashboard tabs support the standard arrow, Home, and End keys, long identifiers wrap safely, reduced-motion preferences disable map animation, and loading, empty, stale, partial-failure, and blocked-notification states are shown explicitly. The toolbar remains visible while its content scrolls, and the normal NPMplus page header and footer remain part of the page.

## Secrets and certificate plugins

Use mounted secret files instead of literal secret values in Compose. NPMplus supports `_FILE` variants for `COOKIE_SECRET`, `OIDC_CLIENT_SECRET`, `INITIAL_ADMIN_PASSWORD`, `INITIAL_SETUP_TOKEN`, `ACME_EAB_HMAC_KEY`, `DB_MYSQL_PASSWORD`, and `DB_POSTGRES_PASSWORD`. The sample `compose.yaml` contains commented Compose-secret examples. Do not set both a value and its `_FILE` variant. A custom `INITIAL_SETUP_TOKEN` must contain at least 32 characters; operator-supplied secret files are not deleted by NPMplus.

NPMplus no longer installs missing Certbot DNS plugins into the running application container by default. Build every required provider plugin into a reviewed custom image with pinned dependencies. A missing plugin is logged without keeping the API offline, but certificate requests and renewals that need it will fail until it is provided. `ALLOW_RUNTIME_CERTBOT_PLUGIN_INSTALL=true` restores the old behavior only as an explicit compatibility escape hatch; it downloads executable code into the live container and exposes the certificate's DNS credential to that code, so it should not be a permanent configuration.

Reset a SQLite user's password without placing it in shell history or process arguments:

```bash
read -rsp 'New NPMplus password: ' NPMPLUS_NEW_PASSWORD; echo
printf '%s' "$NPMPLUS_NEW_PASSWORD" | \
  sudo docker exec -i npmplus password-reset.js user@example.com --password-stdin
unset NPMPLUS_NEW_PASSWORD
```

Append `--disable-mfa` when both the password and MFA need to be reset.

## Backups and restoration

Daily archives are written to `/var/backups/npmplus/npmplus-YYYY-MM-DD-HHMMSS.tar.gz`, mode `0600`, with the newest seven retained. They contain NPMplus data and certificates, CrowdSec state, the generated Compose file, and optional Anubis policy. While NPMplus is running, the helper creates `npmplus/database.backup.sqlite` through SQLite's backup API and includes it in the archive.

To restore an archive, stop the stack, extract the selected archive at the filesystem root, promote the consistent database copy when present, and start the stack:

```bash
sudo docker compose -f /opt/npmplus/compose.yaml down
sudo tar -xzf /var/backups/npmplus/npmplus-YYYY-MM-DD-HHMMSS.tar.gz -C /
if sudo test -f /opt/npmplus/npmplus/database.backup.sqlite; then
  sudo cp -a /opt/npmplus/npmplus/database.backup.sqlite /opt/npmplus/npmplus/database.sqlite
  sudo rm -f /opt/npmplus/npmplus/database.sqlite-wal /opt/npmplus/npmplus/database.sqlite-shm
fi
sudo docker compose -f /opt/npmplus/compose.yaml up -d
```

Choose the archive explicitly and retain a copy until the restored stack has been verified.

## Uninstalling

The normal uninstall requires a successful final backup before confirmation:

```bash
sudo /opt/npmplus/setup-npmplus.sh --uninstall
```

If the backup helper is unavailable or fails, the uninstall stops without deleting the installation. `--no-backup` is an explicit escape hatch:

```bash
sudo /opt/npmplus/setup-npmplus.sh --uninstall --no-backup
```

Uninstall removes NPMplus containers, `/opt/npmplus`, optional CrowdSec and Anubis state, and the cron/helper files owned by this script. It retains `/var/backups/npmplus`, container images, unrelated Docker systemd drop-ins, unrelated packages, and all UFW rules. A CrowdSec firewall bouncer is removed only when an ownership marker proves this script installed it.

## Diagnostics

Useful checks and logs:

```bash
sudo docker compose -f /opt/npmplus/compose.yaml ps
sudo docker compose -f /opt/npmplus/compose.yaml logs --tail 200
sudo tail -n 200 /var/log/npmplus-update.log
sudo tail -n 200 /var/log/npmplus-backup.log
sudo tail -n 200 /var/log/npmplus-crowdsec-heal.log
sudo bash crowdsec-doctor.sh
```

For a failure after reboot, run the read-only boot tracer before manually restarting Docker or the Compose stack. This preserves the failed state in its report:

```bash
sudo bash npmplus-boot-trace.sh
```

If the repository is not present on the VM, install the tracer directly from this fork:

```bash
curl -fL --retry 5 -o /tmp/npmplus-boot-trace.sh \
  https://raw.githubusercontent.com/mangyan1/NPMplus/develop/npmplus-boot-trace.sh
sudo install -m 0755 /tmp/npmplus-boot-trace.sh /usr/local/sbin/npmplus-boot-trace
sudo npmplus-boot-trace
```

The report is written with mode `0600` under `/tmp/npmplus-boot-trace-*.log`. It includes systemd's Docker critical chain, network-online services, host and NPMplus resolver files, the current boot journal, container state/restart policy, recent container logs, Docker events, port listeners, and basic resource checks. Review it for hostnames and IP addresses before sharing it.

After a failed update, the last-good directory also contains `failed-ps.txt` and `failed-logs.txt`. The maintenance lock is `/run/lock/npmplus-maintenance.lock`; an update and a backup will not run concurrently.

The GitHub smoke workflow exercises default and alternate installations on disposable Ubuntu runners. It verifies digest-pinned Compose images, administrator login with Compose-sensitive password characters, transactional update health checks, and uninstall preservation of operator-owned Docker configuration.
