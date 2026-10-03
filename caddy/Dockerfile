# syntax=docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM golang:1.26.8-alpine3.23@sha256:33ce311e5eecedee48ec1b84419c1306e9fbd71009f0d5c3f2a6904b579c1ecc AS builder

ARG CADDY_VERSION=v2.11.6
ARG XCADDY_VERSION=v0.4.5

# 2.11.6 ships every dependency newer than the CVE pins this build used to
# force with --replace, and carries the InterpretableV2 usage natively, so the
# cel-go patch and the pin set were removed with the 2.11.6 bump. The source
# check in caddy.yml still gates the binary with govulncheck; re-add a single
# --replace here only if that goes red again.
# XCADDY_SKIP_CLEANUP keeps the build environment for that source check.
RUN apk upgrade --no-cache -a && \
	apk add --no-cache ca-certificates git && \
	GOBIN=/usr/local/bin go install "github.com/caddyserver/xcaddy/cmd/xcaddy@$XCADDY_VERSION" && \
	CGO_ENABLED=0 XCADDY_SETCAP=0 XCADDY_SKIP_CLEANUP=1 xcaddy build "$CADDY_VERSION" --output /usr/bin/caddy && \
	/usr/bin/caddy version

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk upgrade --no-cache -a && apk add --no-cache tzdata
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

ENV HOME=/tmp/caddy
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["nc", "-z", "127.0.0.1", "80"]
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
