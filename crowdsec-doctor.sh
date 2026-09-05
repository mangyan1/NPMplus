#!/bin/bash
# CrowdSec doctor: chases the "CrowdSec rejected the bouncer key" admin UI
# error down the whole chain - container, LAPI, key file, registration,
# what the npmplus container actually sees - and offers to re-register.
# Run as root on the npmplus host: sudo bash crowdsec-doctor.sh
set -uo pipefail

DATA_DIR=/opt/npmplus
KEY="$DATA_DIR/crowdsec/lapi-ui.key"
MKEY="$DATA_DIR/crowdsec/lapi-ui-machine.key"

bouncer_http_code() {
	local key
	key=$(cat "$1" 2>/dev/null || true)
	[[ -n $key ]] || { echo 000; return; }
	printf 'header = "X-Api-Key: %s"\n' "$key" | \
		curl -sS -m 5 -o /dev/null -w '%{http_code}' --config - \
		"$LAPI/v1/decisions?limit=1" 2>/dev/null || echo 000
}

machine_http_code() {
	[[ -n $1 ]] || { echo 000; return; }
	printf '{"machine_id":"npmplus-ui","password":"%s"}' "$1" | \
		curl -sS -m 5 -o /dev/null -w '%{http_code}' -H "Content-Type: application/json" \
		--data-binary @- "$LAPI/v1/watchers/login" 2>/dev/null || echo 000
}
LAPI=http://127.0.0.1:8080

hdr() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok() { printf ' \033[32m[ok]\033[0m %s\n' "$*"; }
bad() { printf ' \033[31m[FAIL]\033[0m %s\n' "$*"; }
note() { printf '        %s\n' "$*"; }
package_is_installed() {
	[[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)" == "install ok installed" ]]
}

fail=0

hdr "1. containers"
for c in crowdsec npmplus; do
	if docker ps --format '{{.Names}}' | grep -qx "$c"; then
		ok "$c running"
	else
		bad "$c NOT running"
		fail=1
	fi
done

hdr "2. LAPI answers on $LAPI (no key - 401/403 expected)"
code=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "$LAPI/v1/decisions?limit=1" 2>/dev/null || echo 000)
case $code in
	401 | 403) ok "LAPI up (no-key answer: $code)" ;;
	000) bad "LAPI unreachable - is the 127.0.0.1:8080 port publish up?"; fail=1 ;;
	*) bad "unexpected no-key answer: $code"; fail=1 ;;
esac

hdr "2b. is the port the container's? (native crowdsec steals it)"
if package_is_installed crowdsec; then
	bad "native crowdsec package is installed on the host"
	note "its daemon binds 127.0.0.1:8080 before the container can, and"
	note "then rejects every key the container's cscli ever registered"
	note "fix: sudo apt remove crowdsec; docker compose -f $DATA_DIR/compose.yaml up -d crowdsec"
	fail=1
elif command -v ss >/dev/null && ss -ltnp 2>/dev/null | grep ':8080' | grep -qv docker-proxy; then
	bad "port 8080 is owned by something other than docker:"
	ss -ltnp 2>/dev/null | grep ':8080' | sed 's/^/        /'
	fail=1
else
	ok "no native crowdsec, docker owns the port"
fi

hdr "3. bouncer key file ($KEY)"
if [[ ! -s "$KEY" ]]; then
	bad "missing or empty"
	fail=1
else
	ok "present ($(wc -c <"$KEY") bytes, mode $(stat -c %a "$KEY"))"
	if grep -q $'\r' "$KEY"; then
		bad "contains CR (crlf) - the LAPI will never accept it"
		fail=1
	else
		ok "no line-ending junk"
	fi
fi

hdr "4. the key the UI backend uses"
kcode=$(bouncer_http_code "$KEY")
if [[ $kcode == 200 ]]; then
	ok "LAPI accepts the key (200)"
else
	bad "LAPI rejects the key: HTTP $kcode"
	fail=1
fi

hdr "5. registration known to crowdsec"
if docker exec crowdsec cscli bouncers list 2>/dev/null | grep -qi "npmplus-ui"; then
	ok "npmplus-ui bouncer exists"
	docker exec crowdsec cscli bouncers list 2>/dev/null | grep -iE "name|npmplus" | head -3 | sed 's/^/        /'
else
	bad "npmplus-ui is NOT in the bouncer list"
	note "the registration was lost - classic cause: crowdsec's sqlite rolled"
	note "back on an unclean shutdown"
	fail=1
fi

hdr "6. what the npmplus container sees (/data/crowdsec/lapi-ui.key)"
if docker exec npmplus sh -c '[ -s /data/crowdsec/lapi-ui.key ]' 2>/dev/null; then
	hmd5=$(md5sum "$KEY" | cut -d' ' -f1)
	cmd5=$(docker exec npmplus md5sum /data/crowdsec/lapi-ui.key 2>/dev/null | cut -d' ' -f1)
	if [[ $hmd5 == "$cmd5" ]]; then
		ok "container sees the same key"
	else
		bad "container sees a DIFFERENT key (container $cmd5, host $hmd5)"
		fail=1
	fi
else
	bad "missing inside the npmplus container - check the $DATA_DIR:/data mount"
	fail=1
fi

hdr "7. machine key (unban + alert context only)"
mcode=$(machine_http_code "$(cat "$MKEY" 2>/dev/null || true)")
if [[ $mcode == 200 ]]; then
	ok "machine login works"
else
	bad "machine login: HTTP $mcode (unban/alerts will fail; the ban list itself still works)"
	fail=1
fi

hdr "8. self-heal"
if [[ -f /etc/cron.d/npmplus-crowdsec-heal ]]; then
	ok "heal cron installed"
else
	bad "heal cron NOT installed - rerun a fresh setup-npmplus.sh --update"
	note "it installs /usr/local/bin/npmplus-crowdsec-heal + the daily cron"
fi
if [[ -s /var/log/npmplus-crowdsec-heal.log ]]; then
	note "last heal log lines:"
	tail -5 /var/log/npmplus-crowdsec-heal.log | sed 's/^/        /'
fi

hdr "9. recent crowdsec auth errors (2h)"
auth_errors=$(docker logs crowdsec --since 2h 2>&1 | grep -iE "api key|bouncer|403" | tail -8)
if [[ -n $auth_errors ]]; then
	printf '        %s\n' "${auth_errors//$'\n'/$'\n        '}"
else
	note "none found"
fi

hdr "10. crowdsec db files (wal rollback leaves these behind)"
db_files=$(find /opt/crowdsec/data -maxdepth 1 -type f -name '*.db*' -print 2>/dev/null)
if [[ -n $db_files ]]; then
	printf '        %s\n' "${db_files//$'\n'/$'\n        '}"
else
	note "no db files found at /opt/crowdsec/data"
fi

if [[ $fail -eq 0 ]]; then
	hdr "everything checks out"
	note "if the UI still shows the error: hard-refresh the page (ctrl-shift-r),"
	note "and log out/in once - a stale browser session can also break the page"
	exit 0
fi

hdr "fix"
if [[ $kcode == 200 && $mcode == 200 ]]; then
	note "both keys are already accepted - nothing to re-register"
	note "follow the notes above for the remaining findings"
	exit 1
fi
read -r -p "re-register the rejected keys now? [y/N] " answer || answer=""
if [[ $answer != "y" ]]; then
	exit 0
fi

if [[ $kcode != 200 ]]; then
	docker exec crowdsec cscli bouncers delete npmplus-ui >/dev/null 2>&1 || true
	key=$(docker exec crowdsec cscli bouncers add npmplus-ui -o raw 2>/dev/null)
	echo "$key" >"$KEY"
	chmod 600 "$KEY"
	code=$(bouncer_http_code "$KEY")
	if [[ $code == 200 ]]; then
		ok "bouncer re-registered, verified against the LAPI (200)"
	else
		bad "still rejected ($code) - run by hand and compare:"
		note "docker exec crowdsec cscli bouncers add npmplus-ui -o raw"
	fi
fi

if [[ $mcode != 200 ]]; then
	pw=$(docker exec crowdsec cscli machines add npmplus-ui -a -f - --force 2>&1 | sed -n 's/^password:[[:space:]]*//p' | head -1)
	if [[ -n $pw ]]; then
		echo "$pw" >"$MKEY"
		chmod 600 "$MKEY"
		code=$(machine_http_code "$pw")
		if [[ $code == 200 ]]; then
			ok "machine re-registered, verified (200)"
		else
			bad "machine login still rejected ($code)"
		fi
	fi
fi
