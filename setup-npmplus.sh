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
SCRIPT_VERSION="1.16"

DATA_DIR="/opt/npmplus"
CROWDSEC_DIR="/opt/crowdsec"
COMPOSE_FILE="$DATA_DIR/compose.yaml"
ADMIN_SECRET_FILE="/run/npmplus-initial-admin-password"
SELF_URL="https://raw.githubusercontent.com/mangyan1/NPMplus/develop/setup-npmplus.sh"
NPMPLUS_IMAGE_CHANNEL="ghcr.io/mangyan1/npmplus:develop"
CADDY_IMAGE_CHANNEL="ghcr.io/mangyan1/npmplus:caddy"
CROWDSEC_IMAGE_CHANNEL="docker.io/crowdsecurity/crowdsec:latest"
DOCKER_INSTALL_URL="https://get.docker.com"
DOCKER_INSTALL_SHA256="2df5f9e0f201a967f454191726d9254625f0f08030af3812c9edcdedc78e9693"
PACKAGECLOUD_INSTALL_URL="https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh"
PACKAGECLOUD_INSTALL_SHA256="3a098063d364ab1e69516d6835d69945d0e4061c003f86a98e7cf307bb79a91e"

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

# --uninstall is deliberately handled before dependency installation, network
# access and docker service changes. Removing an installation must never install
# Docker/curl or rewrite host configuration first.
if [[ "${1:-}" == "--uninstall" ]]; then
	if [[ "${2:-}" != "--no-backup" ]]; then
		if [[ -x /usr/local/bin/npmplus-backup ]]; then
			say "taking one final backup first (kept in /var/backups/npmplus)"
			/usr/local/bin/npmplus-backup || {
				echo "backup failed - uninstall aborted; fix the backup or explicitly use --no-backup" >&2
				exit 1
			}
		elif [[ -d "$DATA_DIR" ]]; then
			echo "backup helper is missing - uninstall aborted; restore the helper or explicitly use --no-backup" >&2
			exit 1
		fi
	fi
	echo "this removes ALL npmplus containers and data (certs, database,"
	echo "crowdsec state) and the crons this script installed. Shared images and"
	echo "unrelated Docker/system packages are left alone."
	read -r -p "type 'uninstall' to confirm: " answer || true
	[[ "${answer:-}" == "uninstall" ]] || { echo "aborted - nothing removed" >&2; exit 1; }

	if [[ -s "$COMPOSE_FILE" ]] && command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
		say "stopping and removing containers"
		docker compose -f "$COMPOSE_FILE" down --remove-orphans || true
	elif command -v docker >/dev/null; then
		say "no usable compose file - removing stray containers by name"
		for c in npmplus crowdsec npmplus-anubis npmplus-caddy; do
			docker rm -f "$c" >/dev/null 2>&1 || true
		done
	fi

	say "removing NPMplus data and tooling"
	rm -rf -- "$DATA_DIR" "$CROWDSEC_DIR" /opt/anubis-data /opt/anubis.yaml
	rm -f /etc/cron.d/npmplus-safe-update /etc/cron.d/npmplus-backup \
		/etc/cron.d/npmplus-crowdsec-heal /etc/cron.d/anubis-honeypot
	rm -f /usr/local/bin/npmplus-safe-update /usr/local/bin/npmplus-backup \
		/usr/local/bin/npmplus-crowdsec-heal /usr/local/bin/anubis-honeypot-ban \
		/usr/local/sbin/npmplus-wait-for-dns
	rm -f /var/log/npmplus-update.log /var/log/npmplus-backup.log /var/log/npmplus-crowdsec-heal.log

	# Remove only the drop-in owned by this script. Other Docker overrides belong
	# to the operator and must survive an NPMplus uninstall.
	rm -f /etc/systemd/system/docker.service.d/10-wait-for-dns.conf
	rmdir /etc/systemd/system/docker.service.d >/dev/null 2>&1 || true
	command -v systemctl >/dev/null && systemctl daemon-reload >/dev/null 2>&1 || true

	# Only remove a firewall bouncer that this script recorded as installed by it.
	if [[ -f /var/lib/npmplus/installed-firewall-bouncer ]]; then
		apt-get remove -y crowdsec-firewall-bouncer >/dev/null 2>&1 || true
		rm -f /var/lib/npmplus/installed-firewall-bouncer
		rmdir /var/lib/npmplus >/dev/null 2>&1 || true
	fi

	if [[ -d /var/backups/npmplus ]]; then
		say "uninstalled - backups kept in /var/backups/npmplus (delete manually if unwanted)"
	else
		say "uninstalled"
	fi
	echo "container images, unrelated packages and ufw rules were left untouched"
	exit 0
fi

fetch() { # fetch <url> [curl args] -> stdout, retries to survive network blips
	local i
	for i in 1 2 3 4 5; do
		curl -sSfL --connect-timeout 10 --max-time 60 "$@" && return 0
		[[ $i -eq 5 ]] || sleep $((i * 2))
	done
	echo "giving up on: $*" >&2
	return 1
}

run_verified_script() { # url sha256: download, verify, then execute
	local url="$1" expected="$2" tmp
	tmp=$(mktemp)
	if ! fetch "$url" -o "$tmp" || ! printf '%s  %s\n' "$expected" "$tmp" | sha256sum -c -; then
		rm -f "$tmp"
		echo "refusing to execute an unverified installer from $url" >&2
		return 1
	fi
	if ! bash "$tmp"; then
		rm -f "$tmp"
		return 1
	fi
	rm -f "$tmp"
}

yaml_quote() { # quote YAML and escape $ so compose preserves it literally
	local value=${1//\$/\$\$}
	value=${value//\'/\'\'}
	printf "'%s'" "$value"
}

scrub_bootstrap_admin_credentials() {
	[[ -s "$COMPOSE_FILE" ]] || return 0
	local tmp
	tmp=$(mktemp "${COMPOSE_FILE}.XXXXXX")
	awk '
		/NPMPLUS_BOOTSTRAP_ADMIN_(MOUNT|ENV|SECRET)_BEGIN/ { skip=1; next }
		skip && /NPMPLUS_BOOTSTRAP_ADMIN_(MOUNT|ENV|SECRET)_END/ { skip=0; next }
		skip { next }
		$0 == "  npmplus:" { in_npmplus=1 }
		in_npmplus && $0 ~ /^  [^ ]/ && $0 != "  npmplus:" { in_npmplus=0 }
		in_npmplus && ($0 ~ /INITIAL_ADMIN_EMAIL=/ || $0 ~ /INITIAL_ADMIN_PASSWORD=/ || $0 ~ /INITIAL_ADMIN_PASSWORD_FILE=/) { next }
		{ print }
	' "$COMPOSE_FILE" >"$tmp"
	chmod 600 "$tmp"
	chown root:root "$tmp"
	mv -f "$tmp" "$COMPOSE_FILE"
}

erase_bootstrap_admin_secret() {
	if [[ -e "$ADMIN_SECRET_FILE" ]]; then
		# Truncate first so an already-mounted Docker secret loses the value too.
		: >"$ADMIN_SECRET_FILE"
		chmod 600 "$ADMIN_SECRET_FILE"
		rm -f "$ADMIN_SECRET_FILE"
	fi
}

finalize_admin_bootstrap() {
	local ready=false response="" _
	for _ in $(seq 1 300); do
		response=$(curl -fkSs --connect-timeout 2 --max-time 5 https://127.0.0.1:81/api 2>/dev/null || true)
		if grep -qE '"status"[[:space:]]*:[[:space:]]*"OK"' <<<"$response" && \
			grep -qE '"setup"[[:space:]]*:[[:space:]]*true' <<<"$response"; then
			ready=true
			break
		fi
		sleep 1
	done
	if [[ "$ready" != "true" ]]; then
		echo "initial administrator was not confirmed; the root-only bootstrap secret remains at $ADMIN_SECRET_FILE" >&2
		return 1
	fi
	say "removing one-time administrator bootstrap credentials"
	scrub_bootstrap_admin_credentials
	erase_bootstrap_admin_secret
}

pin_image() { # mutable channel -> immutable local platform repo digest
	local channel="$1" repository short_repository docker_repository candidate digest=""
	docker pull "$channel" >/dev/null
	repository=${channel%:*}
	short_repository=${repository#docker.io/}
	docker_repository=${short_repository#library/}
	while IFS= read -r candidate; do
		candidate=${candidate%$'\r'}
		case "${candidate%@*}" in
			"$repository" | "$short_repository" | "$docker_repository")
				digest="$candidate"
				break
				;;
		esac
	done < <(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$channel")
	[[ "$digest" =~ @sha256:[0-9a-f]{64}$ ]] || {
		echo "could not resolve an immutable digest for $channel" >&2
		return 1
	}
	# Keep the channel tag before the digest. NPMplus and Caddy deliberately use
	# different tags in the same repository, so dropping it makes their pinned
	# references indistinguishable during a later update.
	printf '%s@%s\n' "$channel" "${digest#*@}"
}

set_compose_service_image() { # set_compose_service_image <service> <image-ref>
	local service="$1" image_ref="$2" tmp
	tmp=$(mktemp "${COMPOSE_FILE}.XXXXXX")
	if ! awk -v service="$service" -v image_ref="$image_ref" '
		$0 == "  " service ":" { in_service=1 }
		in_service && $0 ~ /^  [^ ]/ && $0 != "  " service ":" { in_service=0 }
		in_service && $0 ~ /^    image:/ {
			print "    image: " image_ref
			replaced=1
			next
		}
		{ print }
		END { if (!replaced) exit 1 }
	' "$COMPOSE_FILE" >"$tmp"; then
		rm -f "$tmp"
		echo "could not update image for Compose service $service" >&2
		return 1
	fi
	chmod --reference="$COMPOSE_FILE" "$tmp"
	mv "$tmp" "$COMPOSE_FILE"
}

# The official Anubis image is non-root. A root-owned bind mount lets it read
# the policy but makes the bbolt database and honeypot log unwritable, which
# sends the container into a restart loop. Discover the numeric image user so
# this keeps working if Anubis changes it in a later release.
prepare_anubis_data() { # prepare_anubis_data <image-ref>
	local image_ref="$1" image_user uid gid
	image_user=$(docker image inspect --format '{{.Config.User}}' "$image_ref" 2>/dev/null || true)
	case "$image_user" in
		[0-9]*:[0-9]*) uid=${image_user%%:*}; gid=${image_user#*:} ;;
		[0-9]*) uid=$image_user; gid=$image_user ;;
		*)
			echo "cannot determine the numeric Anubis image user for $image_ref" >&2
			return 1
			;;
	esac
	install -d -m 0750 -o "$uid" -g "$gid" /opt/anubis-data /opt/anubis-data/anubis
	chown -R "$uid:$gid" /opt/anubis-data
}

anubis_latest_version() {
	local latest_url version
	# GitHub's releases/latest web redirect is not subject to the small anonymous
	# REST API quota. Read its final URL, then validate the tag before using it in
	# either a registry reference or a raw-content URL.
	latest_url=$(fetch https://github.com/TecharoHQ/anubis/releases/latest \
		-o /dev/null -w '%{url_effective}\n')
	version=${latest_url##*/}
	[[ "$version" =~ ^v[0-9][0-9A-Za-z._+-]*$ ]] || {
		echo "could not determine the latest Anubis release from $latest_url" >&2
		return 1
	}
	printf '%s\n' "$version"
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

# a native crowdsec daemon binds 127.0.0.1:8080 before the container's
# publish can and then rejects every key this stack registers - the
# debian-packaged firewall bouncer pulls it in via Recommends. sweep it
# whenever we manage the dockerized stack
remove_native_crowdsec() {
	dpkg -s crowdsec >/dev/null 2>&1 || return 0
	say "removing a native crowdsec (its daemon steals the container's lapi port)"
	systemctl disable --now crowdsec >/dev/null 2>&1 || true
	apt-get remove -y -qq crowdsec >/dev/null 2>&1 || true
}

# the generated host tooling (safe-update, backup, key heal + their crons):
# one definition, installed by both the interactive setup and --update
install_host_tooling() {
say "installing monthly safe-update (snapshot -> update -> health check -> auto-revert)"
# the cron needs the setup script at a known path; running via curl|bash has no file to copy
if [[ -f "$0" ]] && head -1 "$0" | grep -q '^#!/bin/bash'; then
	setup_source=$(readlink -f "$0")
	setup_target=$(readlink -f "$DATA_DIR/setup-npmplus.sh" 2>/dev/null || printf '%s/setup-npmplus.sh' "$DATA_DIR")
	[[ "$setup_source" == "$setup_target" ]] || cp -a "$setup_source" "$DATA_DIR/setup-npmplus.sh"
fi
if [[ -s "$DATA_DIR/setup-npmplus.sh" ]]; then
	chmod 700 "$DATA_DIR/setup-npmplus.sh"
	cat >/usr/local/bin/npmplus-safe-update <<'EOF'
#!/bin/bash
# NPMPLUS_SAFE_UPDATE_WRAPPER_VERSION=3
# monthly npmplus update with a safety net: snapshots the running state,
# runs the update, health-checks it, and reverts to the snapshot on failure
set -euo pipefail

COMPOSE_FILE=/opt/npmplus/compose.yaml
SETUP=/opt/npmplus/setup-npmplus.sh
BACKUP=/var/backups/npmplus-last-good
CANDIDATE=${NPMPLUS_SETUP_CANDIDATE:-}

log() { echo "$(date '+%F %T') $*"; }

# Updates, backups and manual maintenance must not race over sqlite/config files.
exec 9>/run/lock/npmplus-maintenance.lock
flock -n 9 || { log "another NPMplus maintenance job is already running"; exit 1; }

revert() {
	log "health check FAILED - reverting to the last good state"
	docker compose -f "$COMPOSE_FILE" ps -a >"$BACKUP/failed-ps.txt" 2>&1 || true
	docker compose -f "$COMPOSE_FILE" logs --no-color --tail 200 >"$BACKUP/failed-logs.txt" 2>&1 || true
	docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
	cp -a "$BACKUP/compose.yaml" "$COMPOSE_FILE"
	if [[ -s "$BACKUP/anubis.yaml" ]]; then
		cp -a "$BACKUP/anubis.yaml" /opt/anubis.yaml
	else
		rm -f /opt/anubis.yaml
	fi
	if [[ -d "$BACKUP/crowdsec" ]]; then
		rm -rf /opt/crowdsec
		cp -a "$BACKUP/crowdsec" /opt/crowdsec
	fi
	if [[ -d "$BACKUP/anubis-data" ]]; then
		rm -rf /opt/anubis-data
		cp -a "$BACKUP/anubis-data" /opt/anubis-data
	fi
	if [[ -s "$BACKUP/database.sqlite" ]]; then
		cp -a "$BACKUP/database.sqlite" /opt/npmplus/npmplus/database.sqlite
		chmod 600 /opt/npmplus/npmplus/database.sqlite
		rm -f /opt/npmplus/npmplus/database.sqlite-wal /opt/npmplus/npmplus/database.sqlite-shm
	fi
	# --update refreshes these before touching images; roll them back as well.
	[[ -s "$BACKUP/setup-npmplus.sh" ]] && cp -a "$BACKUP/setup-npmplus.sh" "$SETUP"
	rm -f /usr/local/bin/npmplus-safe-update /usr/local/bin/npmplus-backup \
		/usr/local/bin/npmplus-crowdsec-heal
	rm -f /etc/cron.d/npmplus-safe-update /etc/cron.d/npmplus-backup \
		/etc/cron.d/npmplus-crowdsec-heal
	for f in npmplus-safe-update npmplus-backup npmplus-crowdsec-heal; do
		[[ -s "$BACKUP/$f" ]] && cp -a "$BACKUP/$f" "/usr/local/bin/$f"
	done
	for f in npmplus-safe-update npmplus-backup npmplus-crowdsec-heal; do
		[[ -s "$BACKUP/cron-$f" ]] && cp -a "$BACKUP/cron-$f" "/etc/cron.d/$f"
	done
	if [[ -s "$BACKUP/override.yaml" ]]; then
		# pin every service back to its exact pre-update image; --pull never keeps
		# a bad :latest from sneaking back in
		docker compose -f "$COMPOSE_FILE" -f "$BACKUP/override.yaml" up -d --pull never
	else
		docker compose -f "$COMPOSE_FILE" up -d --pull never
	fi
	log "reverted - failure diagnostics are in $BACKUP/failed-{ps,logs}.txt"
	exit 1
}

# snapshot the currently running (presumed good) state
mkdir -p "$BACKUP"
chmod 700 "$BACKUP"
cp -a "$COMPOSE_FILE" "$BACKUP/compose.yaml"
cp -a /opt/anubis.yaml "$BACKUP/anubis.yaml" 2>/dev/null || rm -f "$BACKUP/anubis.yaml"
cp -a "$SETUP" "$BACKUP/setup-npmplus.sh"
for f in npmplus-safe-update npmplus-backup npmplus-crowdsec-heal; do
	rm -f "$BACKUP/$f" "$BACKUP/cron-$f"
	cp -a "/usr/local/bin/$f" "$BACKUP/$f" 2>/dev/null || true
	cp -a "/etc/cron.d/$f" "$BACKUP/cron-$f" 2>/dev/null || true
done

# Never update a stack that is already incomplete; it would produce an unsafe
# rollback baseline and could bring an intentionally stopped service online.
while read -r svc; do
	cid=$(docker compose -f "$COMPOSE_FILE" ps --status running -q "$svc" 2>/dev/null)
	[[ -n "$cid" ]] || {
		log "pre-update check failed: $svc is not running"
		exit 1
	}
	health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid")
	[[ "$health" == "none" || "$health" == "healthy" ]] || {
		log "pre-update check failed: $svc health is $health"
		exit 1
	}
done < <(docker compose -f "$COMPOSE_FILE" config --services)
curl -fkSs --connect-timeout 5 --max-time 10 -o /dev/null https://127.0.0.1/ || {
	log "pre-update check failed: public HTTPS listener is not healthy"
	exit 1
}
curl -fkSs --connect-timeout 5 --max-time 10 https://127.0.0.1:81/api | grep -qE '"status"[[:space:]]*:[[:space:]]*"OK"' || {
	log "pre-update check failed: admin API is not healthy"
	exit 1
}

# Take an online sqlite backup before a new image can run migrations. Refuse to
# call an update safe when the rollback database cannot be created.
rm -f "$BACKUP/database.sqlite"
if [[ -f /opt/npmplus/npmplus/database.sqlite ]]; then
	rm -f /opt/npmplus/npmplus/database.pre-update.sqlite
	docker exec npmplus node -e "const d=require('better-sqlite3')('/data/npmplus/database.sqlite',{readonly:true});d.backup('/data/npmplus/database.pre-update.sqlite').then(()=>d.close())"
	cp -a /opt/npmplus/npmplus/database.pre-update.sqlite "$BACKUP/database.sqlite"
	chmod 600 "$BACKUP/database.sqlite"
	rm -f /opt/npmplus/npmplus/database.pre-update.sqlite
fi

# CrowdSec sqlite/WAL and Anubis bbolt copies must be made while their writers
# are stopped. The brief stop occurs before any image changes and each service
# is restarted immediately after its snapshot.
rm -rf "$BACKUP/crowdsec" "$BACKUP/anubis-data"
stopped_svc=""
restart_snapshot_service() {
	if [[ -n "$stopped_svc" ]]; then
		log "restarting $stopped_svc after an interrupted snapshot"
		docker compose -f "$COMPOSE_FILE" start "$stopped_svc" >/dev/null 2>&1 || true
	fi
}
trap restart_snapshot_service EXIT
for spec in "crowdsec:/opt/crowdsec:crowdsec" "anubis:/opt/anubis-data:anubis-data"; do
	IFS=: read -r svc source name <<<"$spec"
	if docker compose -f "$COMPOSE_FILE" config --services | grep -qx "$svc" && [[ -d "$source" ]]; then
		docker compose -f "$COMPOSE_FILE" stop "$svc"
		stopped_svc="$svc"
		rm -rf "$BACKUP/${name:?}"
		if ! cp -a "$source" "$BACKUP/$name"; then
			docker compose -f "$COMPOSE_FILE" start "$svc" || true
			stopped_svc=""
			exit 1
		fi
		docker compose -f "$COMPOSE_FILE" start "$svc"
		stopped_svc=""
	fi
done
trap - EXIT
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
if [[ -n "$CANDIDATE" && "$CANDIDATE" != "$SETUP" ]]; then
	cp -a "$CANDIDATE" "$SETUP" || revert
	chmod 700 "$SETUP" || revert
fi
NPMPLUS_SAFE_UPDATE_ACTIVE=true "$SETUP" --update || revert

# crowdsec hub: refresh the detection signatures (parsers/scenarios/collections);
# a container image update alone never touches them and they live outside the image
if docker compose -f "$COMPOSE_FILE" ps --status running --format '{{.Name}}' 2>/dev/null | grep -qx crowdsec; then
	docker exec crowdsec cscli hub update
	docker exec crowdsec cscli hub upgrade || log "cscli hub upgrade reported failures (kept, check: docker exec crowdsec cscli hub list)"
fi

# Health check every configured service, Docker health where present, both
# NPMplus listeners, and CrowdSec's own LAPI. HTTP error responses must fail.
check() {
	local svc cid state health key machine_password
	while read -r svc; do
		cid=$(docker compose -f "$COMPOSE_FILE" ps -a -q "$svc" 2>/dev/null)
		[[ -n "$cid" ]] || { log "$svc has no container"; return 1; }
		state=$(docker inspect --format '{{.State.Status}}' "$cid")
		[[ "$state" == "running" ]] || { log "$svc state is $state"; return 1; }
		health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid")
		[[ "$health" == "none" || "$health" == "healthy" ]] || { log "$svc health is $health"; return 1; }
	done < <(docker compose -f "$COMPOSE_FILE" config --services)
	curl -fkSs --connect-timeout 5 --max-time 10 -o /dev/null https://127.0.0.1/ || return 1
	curl -fkSs --connect-timeout 5 --max-time 10 https://127.0.0.1:81/api | grep -qE '"status"[[:space:]]*:[[:space:]]*"OK"' || return 1
	if docker compose -f "$COMPOSE_FILE" config --services | grep -qx crowdsec; then
		docker exec crowdsec cscli lapi status >/dev/null 2>&1 || return 1
		key=$(cat /opt/npmplus/crowdsec/lapi-ui.key 2>/dev/null || true)
		[[ -n "$key" ]] || return 1
		[[ "$(curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' -H "X-Api-Key: $key" 'http://127.0.0.1:8080/v1/decisions?limit=1')" == "200" ]] || return 1
		key=$(sed -n 's/^API_KEY=//p' /opt/npmplus/crowdsec/crowdsec.conf 2>/dev/null)
		[[ -n "$key" ]] || return 1
		[[ "$(curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' -H "X-Api-Key: $key" 'http://127.0.0.1:8080/v1/decisions?limit=1')" == "200" ]] || return 1
		machine_password=$(cat /opt/npmplus/crowdsec/lapi-ui-machine.key 2>/dev/null || true)
		[[ -n "$machine_password" ]] || return 1
		[[ "$(curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d "{\"machine_id\":\"npmplus-ui\",\"password\":\"$machine_password\"}" 'http://127.0.0.1:8080/v1/watchers/login')" == "200" ]] || return 1
	fi
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

exec 9>/run/lock/npmplus-maintenance.lock
flock -n 9 || { echo "$(date '+%F %T') another NPMplus maintenance job is already running"; exit 1; }

log() { echo "$(date '+%F %T') $*"; }

# the tars contain private keys and the database, so keep them root-only
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# hot-copy the database with better-sqlite3 so a copy is never torn mid-write;
# the plain live file is still in the tar as a fallback if this ever fails
if ! docker exec npmplus node -e "const d=require('better-sqlite3')('/data/npmplus/database.sqlite',{readonly:true});d.backup('/data/npmplus/database.backup.sqlite').then(()=>d.close())" >/dev/null 2>&1; then
	log "warning: consistent database copy failed, tar will contain the live file"
fi

files=(opt/npmplus opt/crowdsec)
[[ -f /opt/anubis.yaml ]] && files+=(opt/anubis.yaml)
ts=$(date +%F-%H%M%S)
out="$BACKUP_DIR/npmplus-$ts.tar.gz"
tar -czf "$out" -C / "${files[@]}" || { log "backup FAILED (tar)"; exit 1; }
chmod 600 "$out"
rm -f /opt/npmplus/npmplus/database.backup.sqlite
log "backup ok: $out ($(du -h "$out" | cut -f1))"

# roll the oldest off, keep the last KEEP
mapfile -t backups < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'npmplus-*.tar.gz' -printf '%f\n' | sort -r)
for old in "${backups[@]:$KEEP}"; do
	rm -f -- "$BACKUP_DIR/$old"
done
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

# a native crowdsec steals the lapi port and no heal can help while its
# daemon runs - name the cause instead of failing keys forever
dpkg -s crowdsec >/dev/null 2>&1 && log "WARNING: native crowdsec package installed - if keys keep failing, run crowdsec-doctor.sh"

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
		run_verified_script "$DOCKER_INSTALL_URL" "$DOCKER_INSTALL_SHA256"
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
	# The daemon must not snapshot an empty /etc/resolv.conf into host-networked
	# containers. network-online.target is a no-op on some ifupdown/dhcpcd hosts,
	# so also put an explicit resolver-file gate in Docker's startup path.
	if systemctl is-active --quiet systemd-networkd.service; then
		systemctl enable systemd-networkd-wait-online.service >/dev/null 2>&1 || true
	elif systemctl is-active --quiet NetworkManager.service; then
		systemctl enable NetworkManager-wait-online.service >/dev/null 2>&1 || true
	fi
	cat >/usr/local/sbin/npmplus-wait-for-dns <<'EOF'
#!/bin/sh
# Docker copies the host resolver file into existing containers when it starts.
# Wait until DHCP/resolvconf has published at least one server. This intentionally
# checks configuration rather than an Internet hostname, so an offline LAN can
# still start Docker and serve existing proxy routes.
resolver_file=${NPMPLUS_RESOLV_CONF:-/etc/resolv.conf}
if ! awk '$1 == "nameserver" && $2 != "" { found=1; exit } END { exit !found }' \
	"$resolver_file" 2>/dev/null; then
	echo "npmplus: waiting for a nameserver in $resolver_file before Docker starts" >&2
	until awk '$1 == "nameserver" && $2 != "" { found=1; exit } END { exit !found }' \
		"$resolver_file" 2>/dev/null; do
		sleep 1
	done
fi
EOF
	chmod 755 /usr/local/sbin/npmplus-wait-for-dns
	mkdir -p /etc/systemd/system/docker.service.d
	cat >/etc/systemd/system/docker.service.d/10-wait-for-dns.conf <<'UNIT'
[Unit]
After=network-online.target nss-lookup.target systemd-resolved.service dhcpcd.service
Wants=network-online.target

[Service]
ExecStartPre=/usr/local/sbin/npmplus-wait-for-dns
UNIT
	systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Compare this file with GitHub. The remote copy is never executed here. A
# newer version blocks --update so unattended automation cannot keep deploying
# stale host logic; offline checks remain best-effort.
remote_script=$(fetch "$SELF_URL" 2>/dev/null) || remote_script=""
latest_version=$(sed -n 's/^SCRIPT_VERSION="\([^"]*\)".*/\1/p' <<<"$remote_script" | head -1)
remote_hash=""
local_hash=""
if [[ -n "$remote_script" ]]; then
	remote_hash=$(printf '%s\n' "$remote_script" | sha256sum | cut -d' ' -f1)
	[[ -f "$0" ]] && local_hash=$(sha256sum "$0" | cut -d' ' -f1)
fi
if [[ -n "$latest_version" && "$(printf '%s\n%s\n' "$SCRIPT_VERSION" "$latest_version" | sort -V | tail -1)" == "$latest_version" && "$latest_version" != "$SCRIPT_VERSION" ]]; then
	say "notice: this script is v$SCRIPT_VERSION, GitHub has newer v$latest_version"
	echo "review and re-download it first:"
	echo "  wget -qO setup-npmplus.sh $SELF_URL"
	if [[ "${1:-}" == "--update" && "${NPMPLUS_ALLOW_STALE_SCRIPT:-false}" != "true" ]]; then
		echo "update stopped: set NPMPLUS_ALLOW_STALE_SCRIPT=true only if you intentionally accept the old logic" >&2
		exit 1
	fi
elif [[ -n "$remote_hash" && -n "$local_hash" && "$latest_version" == "$SCRIPT_VERSION" && "$remote_hash" != "$local_hash" ]]; then
	echo "warning: GitHub has different content with the same SCRIPT_VERSION; review before updating" >&2
	[[ "${1:-}" != "--update" || "${NPMPLUS_ALLOW_STALE_SCRIPT:-false}" == "true" ]] || exit 1
fi

say "NPMplus interactive setup"

# --update: no prompts, just pull latest images and redeploy the existing install
if [[ "${1:-}" == "--update" ]]; then
	if [[ ! -s "$COMPOSE_FILE" ]]; then
		echo "no existing install at $COMPOSE_FILE - run without --update first" >&2
		exit 1
	fi
	# Initial credentials are one-time bootstrap inputs. Remove legacy inline
	# values before the safe-update wrapper snapshots compose.yaml, so neither
	# the live file nor the new last-good backup retains the password.
	scrub_bootstrap_admin_credentials
	erase_bootstrap_admin_secret
	# Make manual updates use the same transactional snapshot/health/revert path
	# as cron. The environment flag is set only by that wrapper to avoid recursion.
	if [[ "${NPMPLUS_SAFE_UPDATE_ACTIVE:-false}" != "true" ]]; then
		# v1.4 and earlier wrappers called the installed setup copy directly and
		# cannot hand off a freshly downloaded candidate. Replace them before
		# delegation; this also repairs the old copy's missing execute bit.
		if [[ ! -x /usr/local/bin/npmplus-safe-update ]] || \
			! grep -qx '# NPMPLUS_SAFE_UPDATE_WRAPPER_VERSION=3' /usr/local/bin/npmplus-safe-update; then
			install_host_tooling
		fi
		# Repair the v1.6 root-owned Anubis bind mount before the wrapper checks
		# that every service is healthy. Restart only an already crash-looping
		# container; an intentionally stopped service remains stopped.
		if docker inspect npmplus-anubis >/dev/null 2>&1; then
			ANUBIS_CURRENT_IMAGE=$(docker inspect --format '{{.Config.Image}}' npmplus-anubis)
			prepare_anubis_data "$ANUBIS_CURRENT_IMAGE"
			if [[ "$(docker inspect --format '{{.State.Restarting}}' npmplus-anubis)" == "true" ]]; then
				docker restart npmplus-anubis >/dev/null
			fi
		fi
		# Docker can snapshot an empty host resolv.conf into this host-networked
		# container during boot. Its nginx retry cannot see the host file recover
		# because Docker's copy stays empty. Repair that broken resolver before the
		# safe-update wrapper evaluates the rollback baseline.
		if docker inspect npmplus >/dev/null 2>&1 && \
			! docker exec npmplus awk '$1 == "nameserver" && $2 != "" { found=1; exit } END { exit !found }' /etc/resolv.conf >/dev/null 2>&1 && \
			awk '$1 == "nameserver" && $2 != "" { found=1; exit } END { exit !found }' /etc/resolv.conf; then
			say "repairing npmplus container created with an empty boot resolver"
			docker compose -f "$COMPOSE_FILE" up -d --no-deps --force-recreate npmplus
			repaired=false
			for _ in $(seq 1 180); do
				if [[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' npmplus)" == "healthy" ]]; then
					repaired=true
					break
				fi
				sleep 1
			done
			if [[ "$repaired" != "true" ]]; then
				docker logs --tail 100 npmplus >&2 || true
				echo "npmplus resolver repair did not become healthy" >&2
				exit 1
			fi
		fi
		candidate=$(readlink -f "$0")
		chmod 700 "$candidate"
		NPMPLUS_SETUP_CANDIDATE="$candidate" exec /usr/local/bin/npmplus-safe-update
	fi
	say "updating"
	# Resolve update channels once, then persist immutable digests in compose.
	# Later registry tag movement cannot silently change a deployed stack.
	NPMPLUS_IMAGE=$(pin_image "$NPMPLUS_IMAGE_CHANNEL")
	set_compose_service_image npmplus "$NPMPLUS_IMAGE"
	if grep -q "container_name: crowdsec" "$COMPOSE_FILE"; then
		CROWDSEC_IMAGE=$(pin_image "$CROWDSEC_IMAGE_CHANNEL")
		set_compose_service_image crowdsec "$CROWDSEC_IMAGE"
	fi
	if grep -q "container_name: npmplus-caddy" "$COMPOSE_FILE"; then
		CADDY_IMAGE=$(pin_image "$CADDY_IMAGE_CHANNEL")
		set_compose_service_image npmplus-caddy "$CADDY_IMAGE"
	fi
	# refresh the generated host tooling (safe-update, backup, key heal) so
	# improvements reach existing installs, not just fresh ones
	install_host_tooling
	# anubis is release-pinned in the compose; move it to the latest release together
	# with its policy file so the two can never disagree
	if grep -q "npmplus-anubis" "$COMPOSE_FILE"; then
		ANUBIS_VERSION=$(anubis_latest_version)
		ANUBIS_IMAGE=$(pin_image "ghcr.io/techarohq/anubis:$ANUBIS_VERSION")
		set_compose_service_image anubis "$ANUBIS_IMAGE"
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
		# a native crowdsec steals 127.0.0.1:8080 from the container and no
		# key heal can help while it exists - sweep before healing
		remove_native_crowdsec
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
	# Docker can briefly retain a published port while replacing its old
	# container (most often Caddy on port 80). Give that release race one
	# bounded retry; a real port conflict still fails and triggers rollback.
	if ! docker compose -f "$COMPOSE_FILE" up -d; then
		say "deployment did not start cleanly - retrying once after Docker releases ports"
		sleep 3
		docker compose -f "$COMPOSE_FILE" up -d
	fi
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
	confirm "Configure UFW firewall (allow SSH, 80, 443/tcp+udp)?" "y" && USE_UFW="y"
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

say "resolving immutable container image digests"
NPMPLUS_IMAGE=$(pin_image "$NPMPLUS_IMAGE_CHANNEL")
if [[ "$USE_CROWDSEC" == "y" ]]; then
	CROWDSEC_IMAGE=$(pin_image "$CROWDSEC_IMAGE_CHANNEL")
fi
if [[ "$USE_ANUBIS" == "y" ]]; then
	ANUBIS_VERSION=$(anubis_latest_version)
	ANUBIS_IMAGE=$(pin_image "ghcr.io/techarohq/anubis:$ANUBIS_VERSION")
fi
if [[ "$USE_CADDY" == "y" ]]; then
	CADDY_IMAGE=$(pin_image "$CADDY_IMAGE_CHANNEL")
fi

say "writing $COMPOSE_FILE"
mkdir -p "$DATA_DIR"

ENV_ADMIN=""
ADMIN_SECRET_MOUNT=""
ADMIN_SECRET_TOPLEVEL=""
ADMIN_BOOTSTRAP_ENABLED="false"
if [[ -n "$ADMIN_EMAIL" && -n "$ADMIN_PASSWORD" ]]; then
	ADMIN_BOOTSTRAP_ENABLED="true"
	(umask 077; printf '%s' "$ADMIN_PASSWORD" >"$ADMIN_SECRET_FILE")
	ADMIN_PASSWORD=""
	ADMIN_SECRET_MOUNT='    # NPMPLUS_BOOTSTRAP_ADMIN_MOUNT_BEGIN
    secrets:
      - npmplus_initial_admin_password
    # NPMPLUS_BOOTSTRAP_ADMIN_MOUNT_END'
	ENV_ADMIN="    # NPMPLUS_BOOTSTRAP_ADMIN_ENV_BEGIN"$'\n'"      - $(yaml_quote "INITIAL_ADMIN_EMAIL=$ADMIN_EMAIL")"$'\n'"      - \"INITIAL_ADMIN_PASSWORD_FILE=/run/secrets/npmplus_initial_admin_password\""$'\n'"    # NPMPLUS_BOOTSTRAP_ADMIN_ENV_END"
	ADMIN_SECRET_TOPLEVEL="# NPMPLUS_BOOTSTRAP_ADMIN_SECRET_BEGIN
secrets:
  npmplus_initial_admin_password:
    file: $ADMIN_SECRET_FILE
# NPMPLUS_BOOTSTRAP_ADMIN_SECRET_END"
fi
ENV_TZ="      - $(yaml_quote "TZ=$TZ")"
# Disable IPv6 only when the host has no global IPv6 address.
ENV_DISABLE_IPV6=""
FW_IPV6_ENABLED="false"
if command -v ip >/dev/null && ip -6 address show scope global | grep -q 'inet6 '; then
	FW_IPV6_ENABLED="true"
else
	ENV_DISABLE_IPV6="      - \"DISABLE_IPV6=true\""
fi
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
    image: $CROWDSEC_IMAGE
    pull_policy: missing
    network_mode: bridge
    ports:
      - "127.0.0.1:7422:7422"
      - "127.0.0.1:8080:8080"
    environment:
$ENV_TZ
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
	IFS= read -r -d '' ANUBIS_BLOCK <<EOF || true

  anubis:
    container_name: npmplus-anubis
    restart: unless-stopped
    image: $ANUBIS_IMAGE
    pull_policy: missing
    network_mode: bridge
    ports:
      - "127.0.0.1:8923:8923"
    environment:
$ENV_TZ
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
    image: $CADDY_IMAGE
    pull_policy: missing
    network_mode: bridge
    ports:
      - "80:80"
    environment:
$ENV_TZ
EOF
fi

cat >"$COMPOSE_FILE" <<EOF
name: npmplus
services:
  npmplus:
    container_name: npmplus
    restart: unless-stopped
    image: $NPMPLUS_IMAGE
    pull_policy: missing
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
$ADMIN_SECRET_MOUNT
    volumes:
      - "$DATA_DIR:/data"
    environment:
$ENV_TZ
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
$ADMIN_SECRET_TOPLEVEL
EOF

chmod 600 "$COMPOSE_FILE"
mkdir -p "$DATA_DIR/nginx/logs"

if [[ "$USE_ANUBIS" == "y" ]]; then
	say "fetching anubis bot policy $ANUBIS_VERSION (status codes adjusted for auth_request)"
	anubis_policy "$ANUBIS_VERSION" "$CHALLENGE_ALL"
	prepare_anubis_data "$ANUBIS_IMAGE" # subdir holds the honeypot IP log
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
	# A native daemon can already own 127.0.0.1:8080. Remove it before the
	# container attempts to bind, otherwise set -e exits before cleanup runs.
	remove_native_crowdsec
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
			run_verified_script "$PACKAGECLOUD_INSTALL_URL" "$PACKAGECLOUD_INSTALL_SHA256" >/dev/null
			# --no-install-recommends is load-bearing: the debian-packaged
			# bouncer Recommends a native crowdsec daemon, and a native
			# crowdsec binds 127.0.0.1:8080 before the container can - every
			# auth then hits an lapi that knows none of our keys (silent 403s)
			DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends crowdsec-firewall-bouncer
			mkdir -p /var/lib/npmplus
			touch /var/lib/npmplus/installed-firewall-bouncer
			# belt and suspenders for installs predating the flag (and for
			# packagecloud hiccups): never let a native daemon survive here
			remove_native_crowdsec
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
    enabled: $FW_IPV6_ENABLED
EOF
			chmod 600 /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
			systemctl enable --now crowdsec-firewall-bouncer >/dev/null 2>&1 || systemctl restart crowdsec-firewall-bouncer >/dev/null 2>&1 || true
			echo "firewall bouncer: native nftables bans, service crowdsec-firewall-bouncer"
		fi
	fi
fi

if [[ "$USE_UFW" == "y" ]]; then
	say "configuring UFW"
	# `ufw show added` exposes configured rules even while UFW is inactive and
	# catches DENY/LIMIT-only rule sets too.
	if ufw show added 2>/dev/null | grep -qE '^[[:space:]]*ufw[[:space:]]' && ! confirm "UFW already has rules - reset them to the recommended set?" "n"; then
		echo "keeping existing UFW rules - only adding 80/443 if missing"
	else
		SSH_PORT=22
		if [[ -n "${SSH_CONNECTION:-}" ]]; then
			SSH_PORT=${SSH_CONNECTION##* }
		elif command -v sshd >/dev/null; then
			SSH_PORT=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')
			SSH_PORT=${SSH_PORT:-22}
		fi
		SSH_PORT=$(ask "SSH port to keep open" "$SSH_PORT")
		[[ "$SSH_PORT" =~ ^[0-9]+$ && "$SSH_PORT" -ge 1 && "$SSH_PORT" -le 65535 ]] || {
			echo "invalid SSH port; refusing to reset UFW" >&2
			exit 1
		}
		ufw --force reset >/dev/null
		SSH_FROM=""
		if confirm "Restrict ssh to a source subnet (e.g. 192.168.1.0/24)?" "n"; then
			read -r -p "  subnet (blank = anywhere): " SSH_FROM || true
			[[ "$SSH_FROM" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(/([0-9]|[12][0-9]|3[0-2]))?$ ]] || SSH_FROM=""
			[[ -z "$SSH_FROM" ]] && echo "  not a valid cidr - ssh stays reachable from anywhere"
		fi
		if [[ -n "$SSH_FROM" ]]; then
			ufw allow from "$SSH_FROM" to any port "$SSH_PORT" proto tcp comment 'ssh' >/dev/null  # first, so you stay logged in
		else
			ufw allow "$SSH_PORT"/tcp comment 'ssh' >/dev/null # first, so you stay logged in
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

if [[ "$ADMIN_BOOTSTRAP_ENABLED" == "true" ]]; then
	finalize_admin_bootstrap
fi

install_host_tooling

say "done"
if [[ "$EXPOSE_ADMIN" == "y" ]]; then
	echo "admin UI: https://<host>:81"
else
	echo "admin UI: https://localhost:81 via ssh tunnel: ssh -L 8081:localhost:81 <host>"
fi
if [[ "$ADMIN_BOOTSTRAP_ENABLED" != "true" ]]; then
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
