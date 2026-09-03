#!/bin/bash
# Interactive NPMplus deployment script (targets Debian 12/13 and Ubuntu 22.04+)
# Generates a compose.yaml with only the extras you pick (crowdsec, appsec, firewall
# bouncer, anubis, caddy), wires them together, optionally configures UFW, and starts
# everything. Run as root on the Linux docker host.
#
# deliberately only covers the common path; anything fancier -> edit the
# generated compose.yaml yourself afterwards, every option is commented in there.

set -euo pipefail

# bump this on every meaningful change - the script compares it against the
# copy on github at startup and tells the operator when theirs is stale
SCRIPT_VERSION="1.3"

DATA_DIR="/opt/npmplus"
CROWDSEC_DIR="/opt/crowdsec"

say() { printf '\n\033[1;32m== %s\033[0m\n' "$*"; }
ask() { # ask "question" "default" -> answer on stdout, default on empty enter
	local q="$1" def="$2" answer
	read -r -p "$(printf '\033[1m%s\033[0m [%s]: ' "$q" "$def")" answer || true
	echo "${answer:-$def}"
}
askpw() { # askpw "question" "default" -> answer, no default echoed for passwords
	local q="$1" def="$2" answer
	read -rs -p "$(printf '\033[1m%s\033[0m%s: ' "$q" "${def:+ [$def]}")" answer || true
	echo >&2
	echo "${answer:-$def}"
}
confirm() { # confirm "question" "y|n" -> 0 if yes
	local answer
	answer=$(ask "$1" "$2")
	[[ "$answer" == "y" || "$answer" == "Y" || "$answer" == "yes" ]]
}

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }

fetch() { # fetch <url> [curl args] -> stdout, retries to survive network blips
	local i
	for i in 1 2 3 4 5; do
		curl -sSfL "$@" && return 0
		[[ $i -eq 5 ]] || sleep $((i * 2))
	done
	echo "giving up on: $*" >&2
	return 1
}

anubis_latest_version() {
	fetch https://api.github.com/repos/TecharoHQ/anubis/releases/latest | grep -oE '"tag_name": *"[^"]+"' | cut -d'"' -f4
}

# fetch the bot policy for a given anubis release and adapt it for the auth_request
# integration; refuses to deploy if upstream changed the policy format
anubis_policy() { # anubis_policy <version> [challenge_all]
	fetch "https://raw.githubusercontent.com/TecharoHQ/anubis/refs/tags/$1/data/botPolicies.yaml" -o /opt/anubis.yaml
	# auth_request needs 401/403 instead of anubis' scraper-friendly 200s
	sed -E -i 's/^([[:space:]]*CHALLENGE:)[[:space:]]*.*/\1 401/; s/^([[:space:]]*DENY:)[[:space:]]*.*/\1 403/' /opt/anubis.yaml
	# the docs advise against the memory store in production; bbolt survives restarts
	sed -E -i 's/^([[:space:]]*backend:)[[:space:]]*memory$/\1 bbolt/; s/^([[:space:]]*parameters:)[[:space:]]*\{\}$/\1\n      path: \/data\/anubis.bdb/' /opt/anubis.yaml
	# log honeypot-caught IPs so the crowdsec bridge can ban them
	sed -E -i 's/^([[:space:]]*implementation:)[[:space:]]*naive$/\1 naive\n  ip_log_file: \/data\/anubis\/honeypot.addrs/' /opt/anubis.yaml
	if [[ "${2:-}" == "y" ]]; then
		# challenge everything no other rule matched; appended as the last bot rule,
		# so known-good crawlers and allowlisted paths still pass first
		awk '
			/^bots:/ {inb=1}
			inb && !done && /^[A-Za-z]/ && !/^bots:/ {
				print "  # challenge everything that no other rule matched"
				print "  - name: everything-else"
				print "    user_agent_regex: \".*\""
				print "    action: CHALLENGE"
				print ""
				done=1
			}
			{print}
		' /opt/anubis.yaml >/opt/anubis.yaml.tmp && mv /opt/anubis.yaml.tmp /opt/anubis.yaml
	fi
	# a changed upstream format must fail loudly, not silently drop the protection
	grep -q "CHALLENGE: 401" /opt/anubis.yaml || { echo "anubis policy $1: status code sed did not apply - upstream format changed" >&2; exit 1; }
	grep -q "DENY: 403" /opt/anubis.yaml || { echo "anubis policy $1: deny code sed did not apply - upstream format changed" >&2; exit 1; }
	grep -q "backend: bbolt" /opt/anubis.yaml || { echo "anubis policy $1: store sed did not apply - upstream format changed" >&2; exit 1; }
	grep -q "ip_log_file:" /opt/anubis.yaml || { echo "anubis policy $1: honeypot sed did not apply - upstream format changed" >&2; exit 1; }
	[[ "${2:-}" != "y" ]] || grep -q "name: everything-else" /opt/anubis.yaml || { echo "anubis policy $1: catchall rule did not apply - upstream format changed" >&2; exit 1; }
}

register_bouncer() { # $1 = name -> key on stdout (empty on failure)
	local key="" _
	# a heal can hit a name that still exists in the lapi while its key is dead
	# (rolled-back sqlite); cscli add refuses duplicates, so clear the corpse first
	docker exec crowdsec cscli bouncers delete "$1" >/dev/null 2>&1 || true
	for _ in $(seq 1 30); do
		key=$(docker exec crowdsec cscli bouncers add "$1" -o raw 2>/dev/null || true)
		# cscli without -o raw support: pull the key out of the human table
		[[ -n "$key" ]] || key=$(docker exec crowdsec cscli bouncers add "$1" 2>/dev/null | grep -oE '[[:alnum:]]{20,}' || true)
		[[ -n "$key" ]] && { echo "$key"; return 0; }
		sleep 2
	done
	return 1
}

# a key file can exist and still be dead: an unclean shutdown can roll back or
# corrupt crowdsec's sqlite, and then the lapi no longer knows the registration.
# verify = ask the lapi, so a heal only fires on a key it actually rejects.
bouncer_key_works() { # $1 = bouncer key -> 0 when the lapi accepts it
	[[ -n "$1" ]] || return 1
	curl -sS -m 5 -o /dev/null -w '%{http_code}' \
		-H "X-Api-Key: $1" "http://127.0.0.1:8080/v1/decisions?limit=1" 2>/dev/null | grep -q '^200'
}

machine_key_works() { # $1 = machine id, $2 = password -> 0 on a working login
	[[ -n "$2" ]] || return 1
	curl -sS -m 5 -o /dev/null -w '%{http_code}' -H "Content-Type: application/json" \
		-d "{\"machine_id\": \"$1\", \"password\": \"$2\"}" "http://127.0.0.1:8080/v1/watchers/login" 2>/dev/null | grep -q '^200'
}

register_machine() { # $1 = name -> machine password on stdout (empty on failure)
	local out="" password="" _
	for _ in $(seq 1 30); do
		# -a generates the password, -f - dumps the credentials as yaml;
		# the yaml goes to stderr on newer cscli and stdout on older, so merge
		out=$(docker exec crowdsec cscli machines add "$1" -a -f - --force 2>&1 || true)
		# cscli without --force support: plain add, the machine exists case just fails
		password=$(sed -n 's/^password:[[:space:]]*//p' <<<"$out" | head -1)
		if [[ -z "$password" ]]; then
			out=$(docker exec crowdsec cscli machines add "$1" -a -f - 2>&1 || true)
			password=$(sed -n 's/^password:[[:space:]]*//p' <<<"$out" | head -1)
		fi
		[[ -n "$password" ]] && { echo "$password"; return 0; }
		sleep 2
	done
	return 1
}

# --- dependencies (debian/ubuntu) ------------------------------------------------
if ! command -v curl >/dev/null; then
	if confirm "curl is missing - install it via apt?" "y"; then
		apt-get update -qq && apt-get install -y -qq curl
	else
		echo "curl is required" >&2; exit 1
	fi
fi
if ! command -v docker >/dev/null; then
	if confirm "docker is missing - install it via get.docker.com (official script)?" "y"; then
		curl -sSfL https://get.docker.com | sh
	else
		echo "docker is required" >&2; exit 1
	fi
fi
if ! docker compose version >/dev/null 2>&1; then
	echo "docker compose plugin is required (apt: docker-compose-plugin / docker.io)" >&2
	exit 1
fi
# container restart policies only fire once the daemon is up: without this, a
# reboot leaves the whole stack down until someone starts docker by hand
if command -v systemctl >/dev/null; then
	systemctl enable docker.service >/dev/null 2>&1 || true
	# ...and the daemon must not start containers before the vm's dns answers:
	# nginx dies with "no name servers defined" and the ui stays down until
	# restarted by hand. network-online.target is a no-op unless a wait-online
	# service exists, so enable the one matching the active network stack
	if systemctl is-active --quiet systemd-networkd.service; then
		systemctl enable systemd-networkd-wait-online.service >/dev/null 2>&1 || true
	elif systemctl is-active --quiet NetworkManager.service; then
		systemctl enable NetworkManager-wait-online.service >/dev/null 2>&1 || true
	fi
	mkdir -p /etc/systemd/system/docker.service.d
	cat >/etc/systemd/system/docker.service.d/10-wait-for-dns.conf <<'UNIT'
[Unit]
After=network-online.target systemd-resolved.service
Wants=network-online.target
UNIT
	systemctl daemon-reload >/dev/null 2>&1 || true
fi

# compare this file's version against the one on github - the safe-update and
# key-heal crons run this script, so a stale local copy keeps deploying old
# logic silently. best-effort: offline means no notice, never a hard failure
latest_version=$(fetch "https://raw.githubusercontent.com/mangyan1/NPMplus/develop/setup-npmplus.sh" 2>/dev/null |
	sed -n 's/^SCRIPT_VERSION="\([^"]*\)".*/\1/p' | head -1) || true
if [[ -n "$latest_version" && "$latest_version" != "$SCRIPT_VERSION" ]]; then
	say "notice: this script is v$SCRIPT_VERSION, the latest on github is v$latest_version"
	echo "re-download it first, then run again:"
	echo "  wget -qO setup-npmplus.sh https://raw.githubusercontent.com/mangyan1/NPMplus/develop/setup-npmplus.sh"
fi

say "NPMplus interactive setup"

COMPOSE_FILE="$DATA_DIR/compose.yaml"

# --uninstall: remove everything this script installed. a final backup is
# taken first (kept in /var/backups/npmplus) so a reinstall can be seeded
# from it; --no-backup skips that. everything else goes: containers, images,
# data dirs, crons, helper scripts, the docker systemd dropin and the
# native crowdsec packages (a leftover native crowdsec silently steals the
# lapi port from the container). UFW rules are left alone - they are the
# host's firewall, review with `ufw status numbered`
if [[ "${1:-}" == "--uninstall" ]]; then
	if [[ "${2:-}" != "--no-backup" ]] && [[ -x /usr/local/bin/npmplus-backup ]]; then
		say "taking one final backup first (kept in /var/backups/npmplus)"
		/usr/local/bin/npmplus-backup || echo "backup failed - continuing anyway" >&2
	fi
	echo "this removes ALL npmplus containers, images, data (certs, database,"
	echo "crowdsec state) and the crons this script installed."
	read -r -p "type 'uninstall' to confirm: " answer || true
	[[ "${answer:-}" == "uninstall" ]] || { echo "aborted - nothing removed" >&2; exit 1; }

	if [[ -s "$COMPOSE_FILE" ]]; then
		say "stopping and removing containers + images"
		docker compose -f "$COMPOSE_FILE" down --rmi all --remove-orphans || true
		rm -f "$COMPOSE_FILE"
	else
		say "no compose file - removing stray containers by name"
		for c in npmplus crowdsec npmplus-anubis npmplus-caddy; do
			docker rm -f "$c" >/dev/null 2>&1 || true
		done
	fi

	say "removing data dirs"
	rm -rf "$DATA_DIR" /opt/crowdsec /opt/anubis-data /opt/anubis.yaml

	say "removing crons and helper scripts"
	rm -f /etc/cron.d/npmplus-safe-update /etc/cron.d/npmplus-backup \
		/etc/cron.d/npmplus-crowdsec-heal /etc/cron.d/anubis-honeypot
	rm -f /usr/local/bin/npmplus-safe-update /usr/local/bin/npmplus-backup \
		/usr/local/bin/npmplus-crowdsec-heal /usr/local/bin/anubis-honeypot-ban
	rm -f /var/log/npmplus-update.log /var/log/npmplus-backup.log /var/log/npmplus-crowdsec-heal.log

	say "removing the docker systemd dropin"
	rm -rf /etc/systemd/system/docker.service.d
	systemctl daemon-reload >/dev/null 2>&1 || true

	say "removing native crowdsec packages"
	# a native crowdsec squats 127.0.0.1:8080 and silently breaks the whole
	# dockerized stack whenever it wins the bind race at boot - it must not
	# survive an uninstall
	apt-get remove -y crowdsec crowdsec-firewall-bouncer >/dev/null 2>&1 || true
	apt-get autoremove -y >/dev/null 2>&1 || true

	if [[ -d /var/backups/npmplus ]]; then
		say "uninstalled - backups kept in /var/backups/npmplus (delete manually if unwanted)"
	else
		say "uninstalled"
	fi
	echo "ufw rules were left untouched - review with: ufw status numbered"
	exit 0
fi

# --update: no prompts, just pull latest images and redeploy the existing install
if [[ "${1:-}" == "--update" ]]; then
	if [[ ! -s "$COMPOSE_FILE" ]]; then
		echo "no existing install at $COMPOSE_FILE - run without --update first" >&2
		exit 1
	fi
	say "updating"
	# anubis is release-pinned in the compose; move it to the latest release together
	# with its policy file so the two can never disagree
	if grep -q "npmplus-anubis" "$COMPOSE_FILE"; then
		ANUBIS_VERSION=$(anubis_latest_version)
		sed -i -E "s|(image: ghcr.io/techarohq/anubis:).*|\1$ANUBIS_VERSION|" "$COMPOSE_FILE"
		# keep the catchall choice from the existing policy
		CATCHALL="n"
		grep -q "name: everything-else" /opt/anubis.yaml 2>/dev/null && CATCHALL="y"
		say "anubis -> $ANUBIS_VERSION (policy refreshed)"
		anubis_policy "$ANUBIS_VERSION" "$CATCHALL"
	fi
	# installs made before the crowdsec UI page existed have no bouncer
	# key for it - backfill instead of showing "not wired" in the admin UI.
	# a present but rejected key means crowdsec's db lost the registration
	# (unclean shutdown rolled the sqlite back) - re-register then too
	if grep -q "container_name: crowdsec" "$COMPOSE_FILE"; then
		if [[ ! -s "$DATA_DIR/crowdsec/lapi-ui.key" ]] || ! bouncer_key_works "$(cat "$DATA_DIR/crowdsec/lapi-ui.key" 2>/dev/null)"; then
			say "registering the admin UI bouncer (crowdsec live ban view)"
			UIKEY=$(register_bouncer npmplus-ui || true)
			if [[ -n "$UIKEY" ]]; then
				mkdir -p "$DATA_DIR/crowdsec"
				echo "$UIKEY" >"$DATA_DIR/crowdsec/lapi-ui.key"
				chmod 600 "$DATA_DIR/crowdsec/lapi-ui.key"
			fi
		fi
		# same for the machine the unban action and alert context need;
		# bouncer keys are read-only in the lapi, those two need a machine login
		if [[ ! -s "$DATA_DIR/crowdsec/lapi-ui-machine.key" ]] || ! machine_key_works npmplus-ui "$(cat "$DATA_DIR/crowdsec/lapi-ui-machine.key" 2>/dev/null)"; then
			say "registering the admin UI machine (crowdsec unban + alert context)"
			UIPASSWORD=$(register_machine npmplus-ui || true)
			if [[ -n "$UIPASSWORD" ]]; then
				mkdir -p "$DATA_DIR/crowdsec"
				echo "$UIPASSWORD" >"$DATA_DIR/crowdsec/lapi-ui-machine.key"
				chmod 600 "$DATA_DIR/crowdsec/lapi-ui-machine.key"
			fi
		fi
		# the nginx bouncer: installs from before the "-o raw" fix never got a
		# key (crowdsec saw alerts but nothing was enforced at the proxy), and a
		# rejected key is worse - bans silently stop being enforced, no error
		# anywhere. empty or dead -> (re-)register, the bouncer reloads on restart
		CONF="$DATA_DIR/crowdsec/crowdsec.conf"
		if [[ -s "$CONF" ]]; then
			CONFKEY=$(sed -n 's/^API_KEY=//p' "$CONF")
			if [[ -z "$CONFKEY" ]] || ! bouncer_key_works "$CONFKEY"; then
				say "(re-)registering the nginx bouncer (bans must stay enforced)"
				KEY=$(register_bouncer npmplus || true)
				if [[ -n "$KEY" ]]; then
					sed -i "s|^ENABLED=.*|ENABLED=true|" "$CONF"
					sed -i "s|^API_KEY=.*|API_KEY=$KEY|" "$CONF"
					say "restarting npmplus to load the bouncer"
					docker compose -f "$COMPOSE_FILE" restart npmplus
				fi
			fi
		fi
	fi
	docker compose -f "$COMPOSE_FILE" pull
	docker compose -f "$COMPOSE_FILE" up -d
	say "update done - check: docker compose -f $COMPOSE_FILE ps"
	exit 0
fi

TZ=$(ask "Timezone (TZ identifier, e.g. Europe/Berlin)" "$(cat /etc/timezone 2>/dev/null || echo UTC)")
ADMIN_EMAIL=$(ask "Initial admin email (empty = use setup wizard)" "")
ADMIN_PASSWORD=$(askpw "Initial admin password (empty = random, shown in docker logs once)" "")

USE_CROWDSEC="n"; confirm "Enable crowdsec?" "y" && USE_CROWDSEC="y"
USE_APPSEC="n"
USE_FWBOUNCER="n"
if [[ "$USE_CROWDSEC" == "y" ]]; then
	confirm "Enable crowdsec appsec (WAF-style body inspection)?" "n" && USE_APPSEC="y"
	confirm "Enable the crowdsec firewall bouncer (kernel-level IP bans via nftables)?" "y" && USE_FWBOUNCER="y"
fi
USE_ANUBIS="n"; confirm "Enable anubis (anti-bot proof-of-work)?" "y" && USE_ANUBIS="y"
CHALLENGE_ALL="n"
if [[ "$USE_ANUBIS" == "y" ]]; then
	# strongest anti-bot, but breaks non-browser clients (APIs, RSS, uptime
	# monitors) - answer n if a protected host serves those
	confirm "Challenge everything not matched by any rule?" "y" && CHALLENGE_ALL="y"
fi
USE_CADDY="n"; confirm "Enable caddy (port 80 -> https redirect, so NPMplus only serves https)?" "n" && USE_CADDY="y"
# orange cloud only: with plain dns the visitor ips arrive directly and must NOT be
# taken from cloudflare headers (spoofable by anyone then)
USE_CF="n"; confirm "Are your sites proxied through Cloudflare (orange cloud)?" "y" && USE_CF="y"

# HTTP/3 is always available in NPMplus (enable per host in the UI); it needs 443/udp.
USE_UFW="n"
EXPOSE_ADMIN="n"
if ! command -v ufw >/dev/null; then
	if confirm "ufw is not installed - install it via apt?" "y"; then
		apt-get update -qq && apt-get install -y -qq ufw
	else
		echo "skipping host firewall setup" >&2
	fi
fi
if command -v ufw >/dev/null; then
	confirm "Configure UFW firewall (allow 22, 80, 443/tcp+udp)?" "y" && USE_UFW="y"
	if [[ "$USE_UFW" == "y" ]]; then
		confirm "Open the admin UI port 81 to the internet?" "n" && EXPOSE_ADMIN="y"
	fi
fi
# OS security patches; docker engine updates still need a manual apt upgrade
USE_UNATTENDED="n"; confirm "Enable unattended-upgrades (automatic OS security updates)?" "y" && USE_UNATTENDED="y"

if [[ -s "$COMPOSE_FILE" ]]; then
	cp -a "$COMPOSE_FILE" "$COMPOSE_FILE.bak.$(date +%s)"
	echo "existing compose.yaml backed up"
fi

say "writing $COMPOSE_FILE"
mkdir -p "$DATA_DIR"

ENV_ADMIN=""
if [[ -n "$ADMIN_EMAIL" ]]; then
	ENV_ADMIN="      - \"INITIAL_ADMIN_EMAIL=$ADMIN_EMAIL\""
	[[ -n "$ADMIN_PASSWORD" ]] && ENV_ADMIN="$ENV_ADMIN"$'\n'"      - \"INITIAL_ADMIN_PASSWORD=$ADMIN_PASSWORD\""
fi
# no IPv6 on the host, so stop nginx from listening on it entirely
ENV_DISABLE_IPV6="      - \"DISABLE_IPV6=true\""
# needed for real visitor ips in logs/crowdsec when cloudflare proxies the traffic
ENV_CF=""
[[ "$USE_CF" == "y" ]] && ENV_CF="      - \"TRUST_CLOUDFLARE=true\""
ENV_ANUBIS=""
if [[ "$USE_ANUBIS" == "y" ]]; then
	ENV_ANUBIS="      - \"AUTH_REQUEST_ANUBIS_UPSTREAM=http://127.0.0.1:8923\""
fi
ENV_DISABLE_HTTP=""
if [[ "$USE_CADDY" == "y" ]]; then
	ENV_DISABLE_HTTP="      - \"DISABLE_HTTP=true\""
fi
# crowdsec needs the access logs, so LOGROTATE must be on when it is enabled
ENV_LOGROTATE="      - \"LOGROTATE=true\""
[[ "$USE_CROWDSEC" == "y" ]] || ENV_LOGROTATE="#$ENV_LOGROTATE"
# http/3/quic tuning, optional (needs BPF/PERFMON/NET_ADMIN caps, see commented cap_add):
ENV_QUIC_BPF="#      - \"NGINX_QUIC_BPF=true\""

CROWDSEC_BLOCK=""
if [[ "$USE_CROWDSEC" == "y" ]]; then
	IFS= read -r -d '' CROWDSEC_BLOCK <<EOF || true

  crowdsec:
    container_name: crowdsec
    restart: unless-stopped
    image: docker.io/crowdsecurity/crowdsec:latest
    pull_policy: always
    network_mode: bridge
    ports:
      - "127.0.0.1:7422:7422"
      - "127.0.0.1:8080:8080"
    environment:
      - "TZ=$TZ"
      - "USE_WAL=true"
      - "COLLECTIONS=ZoeyVid/npmplus"
    volumes:
      - "$CROWDSEC_DIR/conf:/etc/crowdsec"
      - "$CROWDSEC_DIR/data:/var/lib/crowdsec/data"
      - "$DATA_DIR/nginx/logs:/opt/npmplus/nginx/logs:ro"
EOF
fi

# the firewall bouncer has no docker image, it is a native package that programs
# the host nftables directly - installed in the crowdsec block below

ANUBIS_BLOCK=""
if [[ "$USE_ANUBIS" == "y" ]]; then
	# pin image and policy file to the same release so they cannot drift apart:
	# a policy from main can be newer than the released image and fail to parse
	ANUBIS_VERSION=$(anubis_latest_version)
	IFS= read -r -d '' ANUBIS_BLOCK <<EOF || true

  anubis:
    container_name: npmplus-anubis
    restart: unless-stopped
    image: ghcr.io/techarohq/anubis:$ANUBIS_VERSION
    pull_policy: always
    network_mode: bridge
    ports:
      - "127.0.0.1:8923:8923"
    environment:
      - "TZ=$TZ"
      - "TARGET= " # important: this needs to be and stay one single space
      - "POLICY_FNAME=/etc/botPolicies.yaml"
    volumes:
      - "/opt/anubis.yaml:/etc/botPolicies.yaml:ro"
      - "/opt/anubis-data:/data"
EOF
fi

CADDY_BLOCK=""
if [[ "$USE_CADDY" == "y" ]]; then
	IFS= read -r -d '' CADDY_BLOCK <<EOF || true

  npmplus-caddy:
    container_name: npmplus-caddy
    restart: unless-stopped
    image: ghcr.io/mangyan1/npmplus:caddy
    pull_policy: always
    network_mode: bridge
    ports:
      - "80:80"
    environment:
      - "TZ=$TZ"
EOF
fi

cat >"$COMPOSE_FILE" <<EOF
name: npmplus
services:
  npmplus:
    container_name: npmplus
    restart: unless-stopped
    image: ghcr.io/mangyan1/npmplus:develop
    pull_policy: always
    network_mode: host
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
      - SETGID
#      - BPF # required if you set NGINX_QUIC_BPF to true
#      - PERFMON # required if you set NGINX_QUIC_BPF to true
#      - NET_ADMIN # required if you set NGINX_QUIC_BPF to true
    security_opt:
      - no-new-privileges:true
    volumes:
      - "$DATA_DIR:/data"
    environment:
      - "TZ=$TZ"
$ENV_ADMIN
$ENV_LOGROTATE
$ENV_QUIC_BPF
$ENV_DISABLE_HTTP
$ENV_DISABLE_IPV6
$ENV_CF
$ENV_ANUBIS
$CROWDSEC_BLOCK
$ANUBIS_BLOCK
$CADDY_BLOCK
EOF

chmod 600 "$COMPOSE_FILE" # contains the admin password if one was set
mkdir -p "$DATA_DIR/nginx/logs"

if [[ "$USE_ANUBIS" == "y" ]]; then
	say "fetching anubis bot policy $ANUBIS_VERSION (status codes adjusted for auth_request)"
	anubis_policy "$ANUBIS_VERSION" "$CHALLENGE_ALL"
	mkdir -p /opt/anubis-data/anubis # subdir holds the honeypot IP log
fi

if [[ "$USE_CROWDSEC" == "y" && "$USE_ANUBIS" == "y" ]]; then
	say "installing honeypot -> crowdsec auto-ban (every 5 min via cron)"
	cat >/usr/local/bin/anubis-honeypot-ban <<'EOF'
#!/bin/bash
# bans IPs caught in anubis' honeypot - those hits are proven malicious by
# construction, so no false positives are possible
set -euo pipefail
LOG=/opt/anubis-data/anubis/honeypot.addrs
STATE=/opt/anubis-data/anubis-honeypot.pos
[ -s "$LOG" ] || exit 0
pos=$(cat "$STATE" 2>/dev/null || echo 0)
size=$(stat -c %s "$LOG")
[ "$pos" -gt "$size" ] && pos=0 # anubis resets the file at 64k
[ "$pos" -eq "$size" ] && exit 0
tail -c +$((pos + 1)) "$LOG" | while read -r ip; do
	case "$ip" in
		*[!0-9a-fA-F.:]*) ;; # not an address, skip
		*) docker exec crowdsec cscli decisions add --ip "$ip" --duration 24h --reason anubis-honeypot >/dev/null 2>&1 || true ;;
	esac
done
echo "$size" >"$STATE"
EOF
	chmod +x /usr/local/bin/anubis-honeypot-ban
	printf '*/5 * * * * root /usr/local/bin/anubis-honeypot-ban\n' >/etc/cron.d/anubis-honeypot
	chmod 644 /etc/cron.d/anubis-honeypot
fi

if [[ "$USE_CROWDSEC" == "y" ]]; then
	say "starting crowdsec"
	docker compose -f "$COMPOSE_FILE" up -d crowdsec
	mkdir -p "$CROWDSEC_DIR/conf/acquis.d" "$CROWDSEC_DIR/conf/bouncers"

	say "writing crowdsec acquisition config"
	{
		echo "filenames:"
		echo "  - /opt/npmplus/nginx/logs/*.log"
		echo "labels:"
		echo "  type: npmplus"
		if [[ "$USE_APPSEC" == "y" ]]; then
			echo "---"
			echo "listen_addr: 0.0.0.0:7422"
			echo "appsec_config: crowdsecurity/appsec-default"
			echo "name: appsec"
			echo "source: appsec"
			echo "labels:"
			echo "  type: appsec"
		fi
	} >"$CROWDSEC_DIR/conf/acquis.d/npmplus.yaml"

	# register bouncer keys (retry until the LAPI is up)
	say "registering nginx bouncer (waiting for crowdsec LAPI...)"
	KEY=$(register_bouncer npmplus || true)
	if [[ -z "$KEY" ]]; then
		echo "could not register nginx bouncer automatically." >&2
		echo "run: docker exec crowdsec cscli bouncers add npmplus -o raw" >&2
		echo "then put the key into $DATA_DIR/crowdsec/crowdsec.conf and redeploy" >&2
	else
		say "writing NPMplus bouncer config"
		mkdir -p "$DATA_DIR/crowdsec"
		CONF="$DATA_DIR/crowdsec/crowdsec.conf"
		if [[ ! -s "$CONF" ]]; then
			# same defaults the image would seed on first start
			cat >"$CONF" <<EOF
ENABLED=true
API_URL=http://127.0.0.1:8080
API_KEY=$KEY
USE_TLS_AUTH=false
CACHE_EXPIRATION=1
BOUNCING_ON_TYPE=all
FALLBACK_REMEDIATION=ban
REQUEST_TIMEOUT=3000
UPDATE_FREQUENCY=10
ENABLE_INTERNAL=false
# stream mode caches bans locally (pulled every UPDATE_FREQUENCY), so bans keep
# being enforced if the LAPI is down; live mode fails open on LAPI outages
MODE=stream
SCENARIOS_CONTAINING=
SCENARIOS_NOT_CONTAINING=
EXCLUDE_LOCATION=
BAN_TEMPLATE_PATH=/data/crowdsec/ban.html
REDIRECT_LOCATION=
RET_CODE=
CAPTCHA_PROVIDER=
SECRET_KEY=
SITE_KEY=
CAPTCHA_TEMPLATE_PATH=/data/crowdsec/captcha.html
CAPTCHA_EXPIRATION=3600
APPSEC_URL=
APPSEC_FAILURE_ACTION=passthrough
APPSEC_CONNECT_TIMEOUT=
APPSEC_SEND_TIMEOUT=
APPSEC_PROCESS_TIMEOUT=
ALWAYS_SEND_TO_APPSEC=false
APPSEC_DROP_UNREADABLE_BODY=false
SSL_VERIFY=true
EOF
			# appsec is opt-in only, see issue #3804: empty unless explicitly chosen
			[[ "$USE_APPSEC" == "y" ]] && sed -i 's|^APPSEC_URL=.*|APPSEC_URL=http://127.0.0.1:7422|' "$CONF"
			chmod 600 "$CONF"
		else
			# existing conf: just flip ENABLED and rotate the key
			sed -i "s|^ENABLED=.*|ENABLED=true|" "$CONF"
			sed -i "s|^API_KEY=.*|API_KEY=$KEY|" "$CONF"
			if [[ "$USE_APPSEC" == "y" ]] && grep -q '^APPSEC_URL=$' "$CONF"; then
				sed -i 's|^APPSEC_URL=.*|APPSEC_URL=http://127.0.0.1:7422|' "$CONF"
			fi
		fi
	fi

	# dedicated read-only bouncer for the admin UI's live ban page; the backend
	# reads the key file at request time, so re-runs rotating it need no restart
	say "registering the admin UI bouncer (live ban view)"
	UIKEY=""
	[[ -s "$DATA_DIR/crowdsec/lapi-ui.key" ]] || UIKEY=$(register_bouncer npmplus-ui || true)
	if [[ -n "$UIKEY" ]]; then
		echo "$UIKEY" >"$DATA_DIR/crowdsec/lapi-ui.key"
		chmod 600 "$DATA_DIR/crowdsec/lapi-ui.key"
	else
		echo "could not register the admin UI bouncer - the UI's crowdsec page will show an error" >&2
		echo "run: docker exec crowdsec cscli bouncers add npmplus-ui -o raw" >&2
		echo "then put the key into $DATA_DIR/crowdsec/lapi-ui.key" >&2
	fi

	# machine login for the unban action and the alert context view (bouncer
	# keys are read-only in the lapi); also backfilled by --update above
	say "registering the admin UI machine (unban + alert context)"
	UIPASSWORD=""
	[[ -s "$DATA_DIR/crowdsec/lapi-ui-machine.key" ]] || UIPASSWORD=$(register_machine npmplus-ui || true)
	if [[ -n "$UIPASSWORD" ]]; then
		echo "$UIPASSWORD" >"$DATA_DIR/crowdsec/lapi-ui-machine.key"
		chmod 600 "$DATA_DIR/crowdsec/lapi-ui-machine.key"
	else
		echo "could not register the admin UI machine - unban and alert context will show an error" >&2
		echo "run: docker exec crowdsec cscli machines add npmplus-ui -a -f - --force" >&2
		echo "then put the password into $DATA_DIR/crowdsec/lapi-ui-machine.key" >&2
	fi

	if [[ "$USE_FWBOUNCER" == "y" ]]; then
		say "installing the firewall bouncer (native package, programs the host nftables)"
		# crowdsec publishes no docker image for this bouncer, the deb is the
		# supported install; noninteractive keeps its debconf wizard silent
		if ! command -v crowdsec-firewall-bouncer >/dev/null; then
			curl -sSfL https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash >/dev/null
			# --no-install-recommends is load-bearing: the debian-packaged
			# bouncer Recommends a native crowdsec daemon, and a native
			# crowdsec binds 127.0.0.1:8080 before the container can - every
			# auth then hits an lapi that knows none of our keys (silent 403s)
			DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends crowdsec-firewall-bouncer
			# belt and suspenders for installs predating the flag (and for
			# packagecloud hiccups): never let a native daemon survive here
			if dpkg -s crowdsec >/dev/null 2>&1; then
				say "removing the native crowdsec the bouncer pulled in"
				systemctl disable --now crowdsec >/dev/null 2>&1 || true
				apt-get remove -y -qq crowdsec >/dev/null 2>&1 || true
			fi
		fi
		FWKEY=$(register_bouncer npmplus-firewall || true)
		if [[ -z "$FWKEY" ]]; then
			echo "could not register firewall bouncer automatically." >&2
			echo "run: docker exec crowdsec cscli bouncers add npmplus-firewall -o raw" >&2
			echo "then put the key into /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml and restart the service" >&2
		else
			cat >/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml <<EOF
# generated by setup-npmplus.sh, see https://docs.crowdsec.net/docs/bouncers/firewall/
api_url: http://127.0.0.1:8080
api_key: $FWKEY
update_frequency: 10s
mode: nftables
nftables:
  ipv4:
    enabled: true
  ipv6:
    enabled: false
EOF
			chmod 600 /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
			systemctl enable --now crowdsec-firewall-bouncer >/dev/null 2>&1 || systemctl restart crowdsec-firewall-bouncer >/dev/null 2>&1 || true
			echo "firewall bouncer: native nftables bans, service crowdsec-firewall-bouncer"
		fi
	fi
fi

if [[ "$USE_UFW" == "y" ]]; then
	say "configuring UFW"
	# never silently wipe rules someone set by hand - ask first
	if ufw status | grep -q "ALLOW" && ! confirm "UFW already has rules - reset them to the recommended set?" "n"; then
		echo "keeping existing UFW rules - only adding 80/443 if missing"
	else
		ufw --force reset >/dev/null
		SSH_FROM=""
		if confirm "Restrict ssh to a source subnet (e.g. 192.168.1.0/24)?" "n"; then
			read -r -p "  subnet (blank = anywhere): " SSH_FROM || true
			[[ "$SSH_FROM" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(/([0-9]|[12][0-9]|3[0-2]))?$ ]] || SSH_FROM=""
			[[ -z "$SSH_FROM" ]] && echo "  not a valid cidr - ssh stays reachable from anywhere"
		fi
		if [[ -n "$SSH_FROM" ]]; then
			ufw allow from "$SSH_FROM" to any port 22 proto tcp comment 'ssh' >/dev/null  # first, so you stay logged in
		else
			ufw allow 22/tcp comment 'ssh' >/dev/null          # first, so you stay logged in
		fi
	fi
	ufw allow 80/tcp comment 'http' >/dev/null
	ufw allow 443/tcp comment 'https' >/dev/null
	ufw allow 443/udp comment 'http3-quic' >/dev/null  # required for HTTP/3
	if [[ "$EXPOSE_ADMIN" == "y" ]]; then
		ufw allow 81/tcp comment 'npmplus-admin' >/dev/null
	else
		echo "admin UI stays on localhost - reach it via ssh tunnel: ssh -L 8081:localhost:81 <host>"
	fi
	ufw --force enable >/dev/null
	echo "ufw active: $(ufw status | head -1)"
fi

if [[ "$USE_UNATTENDED" == "y" ]]; then
	say "enabling unattended-upgrades"
	apt-get install -y -qq unattended-upgrades
	printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' >/etc/apt/apt.conf.d/20auto-upgrades
fi

say "deploying"
docker compose -f "$COMPOSE_FILE" up -d

say "installing monthly safe-update (snapshot -> update -> health check -> auto-revert)"
# the cron needs the setup script at a known path; running via curl|bash has no file to copy
if [[ -f "$0" ]]; then
	cp -a "$0" "$DATA_DIR/setup-npmplus.sh"
fi
if [[ -s "$DATA_DIR/setup-npmplus.sh" ]]; then
	cat >/usr/local/bin/npmplus-safe-update <<'EOF'
#!/bin/bash
# monthly npmplus update with a safety net: snapshots the running state,
# runs the update, health-checks it, and reverts to the snapshot on failure
set -euo pipefail

COMPOSE_FILE=/opt/npmplus/compose.yaml
SETUP=/opt/npmplus/setup-npmplus.sh
BACKUP=/opt/npmplus/.last-good

log() { echo "$(date '+%F %T') $*"; }

revert() {
	log "health check FAILED - reverting to the last good state"
	cp -a "$BACKUP/compose.yaml" "$COMPOSE_FILE"
	[[ -s "$BACKUP/anubis.yaml" ]] && cp -a "$BACKUP/anubis.yaml" /opt/anubis.yaml
	# restore the crowdsec config incl. hub items so the signature update reverts too
	[[ -d "$BACKUP/crowdsec-conf" ]] && cp -a "$BACKUP/crowdsec-conf/." /opt/crowdsec/conf/
	if [[ -s "$BACKUP/override.yaml" ]]; then
		# pin every service back to its exact pre-update image; --pull never keeps
		# a bad :latest from sneaking back in
		docker compose -f "$COMPOSE_FILE" -f "$BACKUP/override.yaml" up -d --pull never
	else
		docker compose -f "$COMPOSE_FILE" up -d --pull never
	fi
	log "reverted - the failed state is kept for inspection, next update overwrites it"
	exit 1
}

# snapshot the currently running (presumed good) state
mkdir -p "$BACKUP"
cp -a "$COMPOSE_FILE" "$BACKUP/compose.yaml"
cp -a /opt/anubis.yaml "$BACKUP/anubis.yaml" 2>/dev/null || rm -f "$BACKUP/anubis.yaml"
rm -rf "$BACKUP/crowdsec-conf"
cp -a /opt/crowdsec/conf "$BACKUP/crowdsec-conf" 2>/dev/null || true
{
	echo "services:"
	while read -r svc id; do
		echo "  $svc:"
		echo "    image: \"$id\""
	done < <(for s in $(docker compose -f "$COMPOSE_FILE" config --services); do
		cid=$(docker compose -f "$COMPOSE_FILE" ps -q "$s" 2>/dev/null || true)
		[[ -n "$cid" ]] && echo "$s $(docker inspect --format '{{.Image}}' "$cid")"
	done)
} >"$BACKUP/override.yaml"

log "running update"
"$SETUP" --update || revert

# crowdsec hub: refresh the detection signatures (parsers/scenarios/collections);
# a container image update alone never touches them and they live outside the image
if docker compose -f "$COMPOSE_FILE" ps --status running --format '{{.Name}}' 2>/dev/null | grep -qx crowdsec; then
	docker exec crowdsec cscli hub update
	docker exec crowdsec cscli hub upgrade || log "cscli hub upgrade reported failures (kept, check: docker exec crowdsec cscli hub list)"
fi

# health check: no dead/exited/restarting containers and nginx answers on https
check() {
	local bad
	bad=$(docker compose -f "$COMPOSE_FILE" ps -a --status dead --status exited --status restarting --format '{{.Name}}' 2>/dev/null | head -1)
	[[ -z "$bad" ]] && curl -ksS -m 5 https://127.0.0.1/ >/dev/null 2>&1
}
sleep 30
check || { sleep 60; check || revert; }
log "update healthy - last good snapshot kept in $BACKUP"
EOF
	chmod +x /usr/local/bin/npmplus-safe-update
	printf '37 4 1 * * root /usr/local/bin/npmplus-safe-update >>/var/log/npmplus-update.log 2>&1\n' >/etc/cron.d/npmplus-safe-update
	chmod 644 /etc/cron.d/npmplus-safe-update
	touch /var/log/npmplus-update.log && chmod 640 /var/log/npmplus-update.log
else
	echo "safe-update cron NOT installed: copy setup-npmplus.sh to $DATA_DIR/ manually, then rerun" >&2
fi

say "installing daily data backup (keeps the last 7)"
cat >/usr/local/bin/npmplus-backup <<'EOF'
#!/bin/bash
# daily npmplus backup. the tar contains the data dir (database, certs, htpasswd
# files), the crowdsec dir and the anubis policy. restores: untar into / and, if
# present, copy npmplus/database.backup.sqlite over npmplus/database.sqlite (it
# is the consistent copy, see below), then: docker compose up -d
set -euo pipefail

BACKUP_DIR=/var/backups/npmplus
KEEP=7 # one week of daily backups
LOG=/var/log/npmplus-backup.log
exec >>"$LOG" 2>&1

log() { echo "$(date '+%F %T') $*"; }

# the tars contain private keys and the database, so keep them root-only
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# hot-copy the database with better-sqlite3 so a copy is never torn mid-write;
# the plain live file is still in the tar as a fallback if this ever fails
if ! docker exec npmplus node -e "const d=require('better-sqlite3')('/data/npmplus/database.sqlite',{readonly:true});d.backup('/data/npmplus/database.backup.sqlite').then(()=>d.close())" >/dev/null 2>&1; then
	log "warning: consistent database copy failed, tar will contain the live file"
fi

files="opt/npmplus opt/crowdsec"
[[ -f /opt/anubis.yaml ]] && files="$files opt/anubis.yaml"
ts=$(date +%F-%H%M%S)
out="$BACKUP_DIR/npmplus-$ts.tar.gz"
tar -czf "$out" -C / $files || { log "backup FAILED (tar)"; exit 1; }
chmod 600 "$out"
rm -f /opt/npmplus/npmplus/database.backup.sqlite
log "backup ok: $out ($(du -h "$out" | cut -f1))"

# roll the oldest off, keep the last KEEP
ls -1t "$BACKUP_DIR"/npmplus-*.tar.gz | tail -n +$((KEEP + 1)) | xargs -r rm -f
EOF
chmod +x /usr/local/bin/npmplus-backup
printf '17 2 * * * root /usr/local/bin/npmplus-backup\n' >/etc/cron.d/npmplus-backup
chmod 644 /etc/cron.d/npmplus-backup
touch /var/log/npmplus-backup.log && chmod 640 /var/log/npmplus-backup.log

# crowdsec's sqlite can roll back on an unclean shutdown and silently kill
# every key registration - that already broke this install's ui and nginx
# bouncer. --update heals it, but only when someone runs it, so verify all
# three keys against the lapi daily and re-register the rejected ones here
say "installing crowdsec key heal (daily cron, log: /var/log/npmplus-crowdsec-heal.log)"
cat >/usr/local/bin/npmplus-crowdsec-heal <<'EOF'
#!/bin/bash
set -uo pipefail

LOG=/var/log/npmplus-crowdsec-heal.log
exec >>"$LOG" 2>&1
log() { echo "$(date '+%F %T') $*"; }
DATA_DIR=/opt/npmplus

docker ps --format '{{.Names}}' 2>/dev/null | grep -qx crowdsec || { log "crowdsec not running, skipped"; exit 0; }

bouncer_key_works() { # $1 = bouncer key -> 0 when the lapi accepts it
	[[ -n "$1" ]] || return 1
	curl -sS -m 5 -o /dev/null -w '%{http_code}' \
		-H "X-Api-Key: $1" "http://127.0.0.1:8080/v1/decisions?limit=1" 2>/dev/null | grep -q '^200'
}

machine_key_works() { # $1 = machine id, $2 = password -> 0 on a working login
	[[ -n "$2" ]] || return 1
	curl -sS -m 5 -o /dev/null -w '%{http_code}' -H "Content-Type: application/json" \
		-d "{\"machine_id\": \"$1\", \"password\": \"$2\"}" "http://127.0.0.1:8080/v1/watchers/login" 2>/dev/null | grep -q '^200'
}

register_bouncer() { # $1 = name -> key on stdout (empty on failure)
	local key="" _
	# cscli add refuses duplicates, so clear the dead registration first
	docker exec crowdsec cscli bouncers delete "$1" >/dev/null 2>&1 || true
	for _ in $(seq 1 30); do
		key=$(docker exec crowdsec cscli bouncers add "$1" -o raw 2>/dev/null || true)
		[[ -n "$key" ]] && { echo "$key"; return 0; }
		sleep 2
	done
	return 1
}

register_machine() { # $1 = name -> machine password on stdout (empty on failure)
	local out="" password="" _
	for _ in $(seq 1 30); do
		# the yaml goes to stderr on newer cscli and stdout on older, so merge
		out=$(docker exec crowdsec cscli machines add "$1" -a -f - --force 2>&1 || true)
		password=$(sed -n 's/^password:[[:space:]]*//p' <<<"$out" | head -1)
		[[ -n "$password" ]] && { echo "$password"; return 0; }
		sleep 2
	done
	return 1
}

# 1: the read-only bouncer behind the admin UI's live ban view
if [[ ! -s "$DATA_DIR/crowdsec/lapi-ui.key" ]] || ! bouncer_key_works "$(cat "$DATA_DIR/crowdsec/lapi-ui.key" 2>/dev/null)"; then
	log "ui bouncer key rejected - re-registering"
	key=$(register_bouncer npmplus-ui || true)
	if [[ -n "$key" ]]; then
		echo "$key" >"$DATA_DIR/crowdsec/lapi-ui.key"
		chmod 600 "$DATA_DIR/crowdsec/lapi-ui.key"
		log "ui bouncer healed"
	else
		log "ui bouncer heal FAILED"
	fi
fi

# 2: the machine behind unban + alert context (bouncer keys are read-only)
if [[ ! -s "$DATA_DIR/crowdsec/lapi-ui-machine.key" ]] || ! machine_key_works npmplus-ui "$(cat "$DATA_DIR/crowdsec/lapi-ui-machine.key" 2>/dev/null)"; then
	log "ui machine key rejected - re-registering"
	password=$(register_machine npmplus-ui || true)
	if [[ -n "$password" ]]; then
		echo "$password" >"$DATA_DIR/crowdsec/lapi-ui-machine.key"
		chmod 600 "$DATA_DIR/crowdsec/lapi-ui-machine.key"
		log "ui machine healed"
	else
		log "ui machine heal FAILED"
	fi
fi

# 3: the nginx bouncer - a dead key means bans silently stop being enforced,
# so this one also reloads the bouncer after rewriting the key
CONF="$DATA_DIR/crowdsec/crowdsec.conf"
if [[ -s "$CONF" ]]; then
	confkey=$(sed -n 's/^API_KEY=//p' "$CONF")
	if [[ -z "$confkey" ]] || ! bouncer_key_works "$confkey"; then
		log "nginx bouncer key rejected - re-registering"
		key=$(register_bouncer npmplus || true)
		if [[ -n "$key" ]]; then
			sed -i "s|^ENABLED=.*|ENABLED=true|" "$CONF"
			sed -i "s|^API_KEY=.*|API_KEY=$key|" "$CONF"
			docker compose -f "$DATA_DIR/compose.yaml" restart npmplus >/dev/null 2>&1
			log "nginx bouncer healed, npmplus restarted"
		else
			log "nginx bouncer heal FAILED"
		fi
	fi
fi
EOF
chmod +x /usr/local/bin/npmplus-crowdsec-heal
printf '42 2 * * * root /usr/local/bin/npmplus-crowdsec-heal\n' >/etc/cron.d/npmplus-crowdsec-heal
chmod 644 /etc/cron.d/npmplus-crowdsec-heal
touch /var/log/npmplus-crowdsec-heal.log && chmod 640 /var/log/npmplus-crowdsec-heal.log

say "done"
if [[ "$EXPOSE_ADMIN" == "y" ]]; then
	echo "admin UI: https://<host>:81"
else
	echo "admin UI: https://localhost:81 via ssh tunnel: ssh -L 8081:localhost:81 <host>"
fi
if [[ -z "$ADMIN_EMAIL" || -z "$ADMIN_PASSWORD" ]]; then
	echo "first-run admin credentials are in: docker logs npmplus"
fi
if [[ "$USE_CADDY" == "y" ]]; then
	echo "caddy: port 80 now redirects everything to https"
fi
echo "http/3: enable it per host in the UI; needs 443/udp reachable (ufw: done)"
echo "safe-update: monthly cron, snapshots then updates, auto-reverts on failure (log: /var/log/npmplus-update.log)"
echo "backup: daily cron, 7 kept in /var/backups/npmplus (log: /var/log/npmplus-backup.log)"
if [[ "$USE_ANUBIS" == "y" ]]; then
	echo "anubis: enable per-host via the Auth Request selection in the host form"
fi
if [[ "$USE_CROWDSEC" == "y" && -z "${KEY:-}" ]]; then
	echo "crowdsec: finish manually, see messages above"
fi