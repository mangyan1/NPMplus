# syntax=docker/dockerfile:1.27.0@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e
FROM golang:1.26.8-alpine3.23@sha256:33ce311e5eecedee48ec1b84419c1306e9fbd71009f0d5c3f2a6904b579c1ecc AS builder

ARG CADDY_VERSION=v2.11.4
ARG XCADDY_VERSION=v0.4.5
ARG X_CRYPTO_VERSION=v0.56.0
ARG X_NET_VERSION=v0.57.0
ARG GRPC_VERSION=v1.83.1
ARG CEL_GO_VERSION=v0.29.2

# Caddy 2.11.4 predates cel-go 0.29's InterpretableV2 API. This two-line
# compatibility patch is taken from upstream commit b2693fb63a30e6d7be0972c3645e9a2c0a500e93.
COPY cel-go-0.29.patch /tmp/cel-go-0.29.patch

RUN apk upgrade --no-cache -a && \
	apk add --no-cache ca-certificates git patch && \
	GOBIN=/usr/local/bin go install "github.com/caddyserver/xcaddy/cmd/xcaddy@$XCADDY_VERSION" && \
	go mod download "github.com/caddyserver/caddy/v2@$CADDY_VERSION" && \
	cp -a "$(go env GOMODCACHE)/github.com/caddyserver/caddy/v2@$CADDY_VERSION" /tmp/caddy-source && \
	chmod -R u+w /tmp/caddy-source && \
	patch -d /tmp/caddy-source -p1 < /tmp/cel-go-0.29.patch && \
	CGO_ENABLED=0 XCADDY_SETCAP=0 xcaddy build "$CADDY_VERSION" --output /usr/bin/caddy \
		--with "github.com/caddyserver/caddy/v2=/tmp/caddy-source" \
		--replace "github.com/google/cel-go=github.com/google/cel-go@$CEL_GO_VERSION" \
		--replace "golang.org/x/crypto=golang.org/x/crypto@$X_CRYPTO_VERSION" \
		--replace "golang.org/x/net=golang.org/x/net@$X_NET_VERSION" \
		--replace "google.golang.org/grpc=google.golang.org/grpc@$GRPC_VERSION" && \
	/usr/bin/caddy version

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk upgrade --no-cache -a && apk add --no-cache tzdata
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

ENV HOME=/tmp/caddy
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["nc", "-z", "127.0.0.1", "80"]
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
