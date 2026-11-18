# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
FROM golang:1.26.10-alpine3.23@sha256:34414731924cf2263160f0021f5cf6e1807382d85248f7cb419d4187b96d5e43 AS builder

ARG CADDY_VERSION=v2.11.9
ARG XCADDY_VERSION=v0.4.5

# Keep the source build: caddy.yml's source check runs govulncheck against the
# actual compiled module graph and the upstream HTTP tests. Caddy 2.11.9 ships
# chi v5.4.0 and x/net v0.60.0, so the former targeted replacements are gone.
# If govulncheck goes red against a future release, add only the single needed
# --replace, not the whole old pin set.
RUN apk upgrade --no-cache -a && \
	apk add --no-cache ca-certificates git && \
	GOBIN=/usr/local/bin go install "github.com/caddyserver/xcaddy/cmd/xcaddy@$XCADDY_VERSION" && \
	CGO_ENABLED=0 XCADDY_SETCAP=0 XCADDY_SKIP_CLEANUP=1 xcaddy build "$CADDY_VERSION" --output /usr/bin/caddy && \
	/usr/bin/caddy version

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
