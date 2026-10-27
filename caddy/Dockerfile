# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
FROM golang:1.26.10-alpine3.23@sha256:34414731924cf2263160f0021f5cf6e1807382d85248f7cb419d4187b96d5e43 AS builder

ARG CADDY_VERSION=v2.11.7
ARG X_NET_VERSION=v0.60.0
ARG CHI_VERSION=v5.4.0
ARG XCADDY_VERSION=v0.4.5

# Keep stable Caddy source with targeted x/net and chi security replacements.
# The source check in caddy.yml gates the actual compiled module graph with
# govulncheck and upstream HTTP tests; do not restore obsolete blanket pins.
# XCADDY_SKIP_CLEANUP keeps the build environment for that source check.
RUN apk upgrade --no-cache -a && \
	apk add --no-cache ca-certificates git && \
	GOBIN=/usr/local/bin go install "github.com/caddyserver/xcaddy/cmd/xcaddy@$XCADDY_VERSION" && \
	CGO_ENABLED=0 XCADDY_SETCAP=0 XCADDY_SKIP_CLEANUP=1 xcaddy build "$CADDY_VERSION" --replace "golang.org/x/net=golang.org/x/net@$X_NET_VERSION" --replace "github.com/go-chi/chi/v5=github.com/go-chi/chi/v5@$CHI_VERSION" --output /usr/bin/caddy && \
	/usr/bin/caddy version

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# CVE-2026-85091: invalidate older runtime layers and require the patched zlib.
RUN apk upgrade --no-cache -a && apk add --no-cache tzdata "zlib>=1.3.2-r1"
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

ENV HOME=/tmp/caddy
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["nc", "-z", "127.0.0.1", "80"]
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
