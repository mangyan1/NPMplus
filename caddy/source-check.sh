#!/bin/sh
set -eu

# Check the generated xcaddy module so every replacement matches the binary.
set -- /tmp/buildenv_*
if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
	echo 'Expected one retained xcaddy build directory' >&2
	exit 1
fi
cd "$1"
export CGO_ENABLED=0
export GOFLAGS=-tags=nobadger,nomysql,nopgx
go list -deps ./... > /tmp/caddy-source-dependencies.txt
if grep -F 'golang.org/x/crypto/openpgp' /tmp/caddy-source-dependencies.txt; then
	echo 'Deprecated OpenPGP must not be linked into Caddy' >&2
	exit 1
fi

# JSON mode alone does not return a failing status for reachable findings.
# Use the text-mode exit status as the gate and retain raw module findings in Trivy.
GOBIN=/tmp/caddy-check-bin go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
/tmp/caddy-check-bin/govulncheck ./...
go test github.com/caddyserver/caddy/v2/modules/caddyhttp github.com/caddyserver/caddy/v2/modules/caddyhttp/tracing
