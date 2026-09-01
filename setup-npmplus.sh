#!/bin/bash
# Interactive NPMplus deployment script (targets Debian 12/13 and Ubuntu 22.04+)
# Generates a compose.yaml with only the extras you pick (crowdsec, appsec, firewall
# bouncer, anubis, caddy), wires them together, optionally configures UFW, and starts
# everything. Run as root on the Linux docker host.
#
# deliberately only covers the common path; anything fancier -> edit the
# generated compose.yaml yourself afterwards, every option is commented in there.

set -euo pipefail

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

anubis_latest_version() {
	curl -sSfL https://api.github.com/repos/TecharoHQ/anubis/releases/latest | grep -oE '"tag_name": *"[^"]+"' | cut -d'"' -f4
}

# fetch the bot policy for a given anubis release and adapt it for the auth_request
# integration; refuses to deploy if upstream changed the policy format
anubis_policy() { # anubis_policy <version> [challenge_all]
	curl -sSfL "https://raw.githubusercontent.com/TecharoHQ/anubis/refs/tags/$1/data/botPolicies.yaml" -o /opt/anubis.yaml
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

say "NPMplus interactive setup"

COMPOSE_FILE="$DATA_DIR/compose.yaml"

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

ENV_ADMIN=""
if [[ -n "$ADMIN_EMAIL" ]]; then
	ENV_ADMIN="      - \"INITIAL_ADMIN_EMAIL=$ADMIN_EMAIL\""
	[[ -n "$ADMIN_PASSWORD" ]] && ENV_ADMIN="$ENV_ADMIN"$'\n'"      - \"INITIAL_ADMIN_PASSWORD=$ADMIN_PASSWORD\""
fi
# no IPv6 on the host, so stop nginx from listening on it entirely
ENV_DISABLE_IPV6="      - \"DISABLE_IPV6=true\""
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
	read -r -d '' CROWDSEC_BLOCK <<EOF || true

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

FWBOUNCER_BLOCK=""
if [[ "$USE_FWBOUNCER" == "y" ]]; then
	read -r -d '' FWBOUNCER_BLOCK <<EOF || true

  crowdsec-firewall-bouncer:
    container_name: crowdsec-firewall-bouncer
    restart: unless-stopped
    image: docker.io/crowdsecurity/firewall-bouncer:latest
    pull_policy: always
    # host network + NET_ADMIN: programs the host nftables with crowdsec bans
    network_mode: host
    environment:
      - "TZ=$TZ"
    cap_add:
      - NET_ADMIN
    volumes:
      - "$CROWDSEC_DIR/conf/bouncers:/etc/crowdsec/bouncers"
EOF
fi

ANUBIS_BLOCK=""
if [[ "$USE_ANUBIS" == "y" ]]; then
	# pin image and policy file to the same release so they cannot drift apart:
	# a policy from main can be newer than the released image and fail to parse
	ANUBIS_VERSION=$(anubis_latest_version)
	read -r -d '' ANUBIS_BLOCK <<EOF || true

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
	read -r -d '' CADDY_BLOCK <<EOF || true

  npmplus-caddy:
    container_name: npmplus-caddy
    restart: unless-stopped
    image: docker.io/zoeyvid/npmplus:caddy
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
    image: docker.io/zoeyvid/npmplus:latest
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
$ENV_ANUBIS
$CROWDSEC_BLOCK
$FWBOUNCER_BLOCK
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
	register_bouncer() { # $1 = name -> key on stdout (empty on failure)
		local key="" _
		for _ in $(seq 1 30); do
			key=$(docker exec crowdsec cscli bouncers add "$1" --raw 2>/dev/null || true)
			[[ -n "$key" ]] && { echo "$key"; return 0; }
			sleep 2
		done
		return 1
	}

	say "registering nginx bouncer (waiting for crowdsec LAPI...)"
	KEY=$(register_bouncer npmplus || true)
	if [[ -z "$KEY" ]]; then
		echo "could not register nginx bouncer automatically." >&2
		echo "run: docker exec crowdsec cscli bouncers add npmplus" >&2
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

	if [[ "$USE_FWBOUNCER" == "y" ]]; then
		say "registering firewall bouncer"
		FWKEY=$(register_bouncer npmplus-firewall || true)
		if [[ -z "$FWKEY" ]]; then
			echo "could not register firewall bouncer automatically." >&2
			echo "run: docker exec crowdsec cscli bouncers add npmplus-firewall" >&2
			echo "then put the key into $CROWDSEC_DIR/conf/bouncers/crowdsec-firewall-bouncer.yaml" >&2
		else
			mkdir -p "$CROWDSEC_DIR/conf/bouncers"
			cat >"$CROWDSEC_DIR/conf/bouncers/crowdsec-firewall-bouncer.yaml" <<EOF
# generated by setup-npmplus.sh, see https://docs.crowdsec.net/docs/bouncers/firewall/
api_url: http://127.0.0.1:8080
api_key: $FWKEY
update_frequency: 10s
daemonize: false
log_mode: stderr
log_level: info
nftables:
  ipv4:
    enabled: true
  ipv6:
    enabled: true
EOF
			chmod 600 "$CROWDSEC_DIR/conf/bouncers/crowdsec-firewall-bouncer.yaml"
			echo "firewall bouncer: nftables bans (note: docker-published ports may need extra rules, see README crowdsec step 11)"
		fi
	fi
fi

if [[ "$USE_UFW" == "y" ]]; then
	say "configuring UFW"
	ufw --force reset >/dev/null
	ufw allow 22/tcp comment 'ssh' >/dev/null          # first, so you stay logged in
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

mkdir -p "$BACKUP_DIR"

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
rm -f /opt/npmplus/npmplus/database.backup.sqlite
log "backup ok: $out ($(du -h "$out" | cut -f1))"

# roll the oldest off, keep the last KEEP
ls -1t "$BACKUP_DIR"/npmplus-*.tar.gz | tail -n +$((KEEP + 1)) | xargs -r rm -f
EOF
chmod +x /usr/local/bin/npmplus-backup
printf '17 2 * * * root /usr/local/bin/npmplus-backup\n' >/etc/cron.d/npmplus-backup
chmod 644 /etc/cron.d/npmplus-backup
touch /var/log/npmplus-backup.log && chmod 640 /var/log/npmplus-backup.log

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