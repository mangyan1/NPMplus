# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
FROM golang:1.26.11-alpine3.23@sha256:23f198931d4bd83b4f5a613bd75656257ae8bf832dcbc2db80e1050b5219ca2a AS builder

ARG CADDY_VERSION=v2.11.9
ARG XCADDY_VERSION=v0.4.5

# Keep the source build: caddy.yml's source check runs govulncheck against the
# actual compiled module graph and the upstream HTTP tests. Caddy 2.11.9 ships
# chi v5.4.0, but its dependency set is newer than the release: replace only the
# modules needed for the currently reachable advisories, and keep the list
# minimal. If govulncheck goes red again, add the single needed --replace.
#   GO-2026-6859  net/http          -> Go 1.26.11 builder above
#   GO-2026-6865  klauspost/compress -> v1.20.2
#   CVE-2026-78661/97045 golang.org/x/net -> v0.62.0
#   CVE-2026-116585/6/7 go-jose/v3 -> smallstep/certificates master + crypto v0.92 (go-jose/v4)
#   CVE-2026-128085 otel sdk/log/trace -> v1.47.0
RUN apk upgrade --no-cache -a && apk add --no-cache ca-certificates git && GOBIN=/usr/local/bin go install "github.com/caddyserver/xcaddy/cmd/xcaddy@$XCADDY_VERSION" && CGO_ENABLED=0 XCADDY_SETCAP=0 XCADDY_SKIP_CLEANUP=1 xcaddy build "$CADDY_VERSION" --replace "github.com/klauspost/compress=github.com/klauspost/compress@v1.20.2" --replace "golang.org/x/net=golang.org/x/net@v0.62.0" --replace "github.com/smallstep/certificates=github.com/smallstep/certificates@v0.30.3-0.20261110092624-0d8a80647845" --replace "go.step.sm/crypto=go.step.sm/crypto@v0.92.0" --replace "go.opentelemetry.io/otel=go.opentelemetry.io/otel@v1.47.0" --replace "go.opentelemetry.io/otel/sdk=go.opentelemetry.io/otel/sdk@v1.47.0" --replace "go.opentelemetry.io/otel/trace=go.opentelemetry.io/otel/trace@v1.47.0" --replace "go.opentelemetry.io/otel/metric=go.opentelemetry.io/otel/metric@v1.47.0" --replace "go.opentelemetry.io/otel/log=go.opentelemetry.io/otel/log@v1.47.0" --replace "go.opentelemetry.io/otel/sdk/log=go.opentelemetry.io/otel/sdk/log@v1.47.0" --output /usr/bin/caddy && /usr/bin/caddy version

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
# CVE-2026-85091: invalidate older runtime layers and require the patched zlib.
RUN apk upgrade --no-cache -a && apk add --no-cache tzdata "zlib>=1.3.2-r1"
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

ENV HOME=/tmp/caddy
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["nc", "-z", "127.0.0.1", "80"]
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
