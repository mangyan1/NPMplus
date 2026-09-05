#!/bin/bash
# Read-only boot diagnostics for NPMplus. Run after a failed reboot and before
# manually starting the stack so the original systemd/container state is kept.
set -uo pipefail

if [[ -n ${1:-} ]]; then
	OUT=$1
	umask 077
	if ! (set -o noclobber; : >"$OUT") 2>/dev/null; then
		echo "refusing to overwrite diagnostic report: $OUT" >&2
		exit 1
	fi
else
	OUT=$(mktemp "/tmp/npmplus-boot-trace-$(date +%Y%m%d-%H%M%S).XXXXXX.log")
fi
COMPOSE=/opt/npmplus/compose.yaml
BOOT_TIME=$(date -d "$(uptime -s)" --iso-8601=seconds)
NOW=$(date --iso-8601=seconds)

chmod 600 "$OUT"
exec > >(tee "$OUT") 2>&1

section() {
	printf '\n========== %s ==========\n' "$*"
}

run() {
	printf '\n$'
	printf ' %q' "$@"
	printf '\n'
	"$@" || true
}

section "HOST AND BOOT"
run date --iso-8601=seconds
run uptime
run systemd-analyze time
run systemd-analyze critical-chain docker.service
run bash -c 'systemd-analyze blame --no-pager | head -50'

section "DOCKER SERVICE"
run systemctl is-enabled docker.service
run systemctl status docker.service --no-pager -l
run systemctl show docker.service \
	--property=ActiveState,SubState,Result,ExecMainStatus,ActiveEnterTimestamp,After,Wants
run systemctl cat docker.service
run systemctl list-dependencies --all docker.service

section "NETWORK AND DNS"
for unit in \
	network-online.target \
	systemd-networkd.service \
	systemd-networkd-wait-online.service \
	NetworkManager.service \
	NetworkManager-wait-online.service \
	systemd-resolved.service; do
	run systemctl status "$unit" --no-pager -l
done

run ip -brief address
run readlink -f /etc/resolv.conf
run cat /etc/resolv.conf
run getent ahosts ghcr.io
if command -v resolvectl >/dev/null; then
	run resolvectl query ghcr.io
	run resolvectl status
fi

section "CURRENT-BOOT JOURNAL"
run journalctl -b --no-pager -n 500 \
	-u docker.service \
	-u containerd.service \
	-u systemd-networkd-wait-online.service \
	-u NetworkManager-wait-online.service \
	-u systemd-resolved.service

section "BOOT WARNINGS"
run journalctl -b --no-pager -p warning..alert -n 250

section "CONTAINERS"
run docker info --format \
	'Docker={{.ServerVersion}} started={{.SystemTime}} containers={{.Containers}} running={{.ContainersRunning}}'

if [[ -s "$COMPOSE" ]]; then
	run docker compose -f "$COMPOSE" config --services
	run docker compose -f "$COMPOSE" config --images
	run docker compose -f "$COMPOSE" ps -a

	mapfile -t services < <(docker compose -f "$COMPOSE" config --services 2>/dev/null)
	for service in "${services[@]}"; do
		section "CONTAINER: $service"
		cid=$(docker compose -f "$COMPOSE" ps -a -q "$service" 2>/dev/null || true)
		if [[ -z "$cid" ]]; then
			echo "No container exists for service $service."
			continue
		fi

		run docker inspect --format \
			'name={{.Name}} state={{.State.Status}} exit={{.State.ExitCode}} error={{printf "%q" .State.Error}} started={{.State.StartedAt}} finished={{.State.FinishedAt}} restart={{.HostConfig.RestartPolicy.Name}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
			"$cid"
		if [[ "$service" == "npmplus" ]]; then
			run docker exec "$cid" cat /etc/resolv.conf
		fi
		run docker logs --since "$BOOT_TIME" --tail 200 "$cid"
	done
else
	echo "$COMPOSE is missing."
fi

section "CONTAINER EVENTS SINCE BOOT"
run docker events \
	--since "$BOOT_TIME" \
	--until "$NOW" \
	--filter type=container \
	--format '{{.Time}} {{.Action}} {{.Actor.Attributes.name}} {{.Actor.Attributes.exitCode}}'

section "PORTS AND RESOURCES"
run bash -c "ss -lntp | grep -E ':(80|81|443|7422|8080|8923)([[:space:]]|$)' || true"
run df -h / /var/lib/docker
run free -h

section "QUICK INTERPRETATION"
echo "If critical-chain stops at *-wait-online.service, networking is delaying Docker."
echo "If Docker is active but no container exists, compose down probably removed it."
echo "If restart=unless-stopped and exit=0, the container may have been manually stopped."
echo "Look for DNS/resolver errors in the npmplus logs."
echo "Look for port conflicts when a container repeatedly exits."
echo
echo "Report saved to: $OUT"
echo "Review it for hostnames and IP addresses before sharing it."
