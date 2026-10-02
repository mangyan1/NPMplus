# syntax=docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM golang:1.26.8-alpine3.23@sha256:33ce311e5eecedee48ec1b84419c1306e9fbd71009f0d5c3f2a6904b579c1ecc AS builder

ARG CADDY_VERSION=v2.11.4
ARG XCADDY_VERSION=v0.4.5
ARG X_CRYPTO_VERSION=v0.56.0
ARG X_NET_VERSION=v0.57.0
# v1.83.2 fixes GHSA-2v4p-qf9q-27wj (CVE-2026-84445): xDS servers crash on
# requests missing both :authority and Host headers.
ARG GRPC_VERSION=v1.83.2
ARG CEL_GO_VERSION=v0.30.0
ARG CHI_VERSION=v5.3.0
ARG COMPRESS_VERSION=v1.18.7
# Caddy 2.11.4 pins the OTLP log modules at v0.19.0. That exporter accepted a
# TLS certificate without validating it (CVE-2026-81871, fixed in v0.21.0).
# The log modules carry their own v0.x line, so pin the whole set to the
# aligned otel v1.45.0 release, including the trace exporters (CVE-2026-81870).
ARG OTEL_VERSION=v1.45.0
ARG OTEL_LOG_VERSION=v0.21.0

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
	CGO_ENABLED=0 XCADDY_SETCAP=0 XCADDY_SKIP_CLEANUP=1 xcaddy build "$CADDY_VERSION" --output /usr/bin/caddy \
		--with "github.com/caddyserver/caddy/v2@$CADDY_VERSION=/tmp/caddy-source" \
		--replace "github.com/google/cel-go=github.com/google/cel-go@$CEL_GO_VERSION" \
		--replace "github.com/go-chi/chi/v5=github.com/go-chi/chi/v5@$CHI_VERSION" \
		--replace "github.com/klauspost/compress=github.com/klauspost/compress@$COMPRESS_VERSION" \
		--replace "golang.org/x/crypto=golang.org/x/crypto@$X_CRYPTO_VERSION" \
		--replace "golang.org/x/net=golang.org/x/net@$X_NET_VERSION" \
		--replace "google.golang.org/grpc=google.golang.org/grpc@$GRPC_VERSION" \
		--replace "go.opentelemetry.io/otel=go.opentelemetry.io/otel@$OTEL_VERSION" \
		--replace "go.opentelemetry.io/otel/log=go.opentelemetry.io/otel/log@$OTEL_LOG_VERSION" \
		--replace "go.opentelemetry.io/otel/sdk/log=go.opentelemetry.io/otel/sdk/log@$OTEL_LOG_VERSION" \
		--replace "go.opentelemetry.io/otel/exporters/otlp/otlptrace=go.opentelemetry.io/otel/exporters/otlp/otlptrace@$OTEL_VERSION" \
		--replace "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc=go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@$OTEL_VERSION" \
		--replace "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp=go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@$OTEL_VERSION" \
		--replace "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc=go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc@$OTEL_LOG_VERSION" \
		--replace "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp=go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp@$OTEL_LOG_VERSION" \
		--replace "go.opentelemetry.io/otel/exporters/stdout/stdoutlog=go.opentelemetry.io/otel/exporters/stdout/stdoutlog@$OTEL_LOG_VERSION" && \
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
