# syntax=docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM golang:1.26.8-alpine3.23@sha256:33ce311e5eecedee48ec1b84419c1306e9fbd71009f0d5c3f2a6904b579c1ecc AS builder

ARG ANUBIS_COMMIT=d39e26cedcc96bea5e4915297c756e7eec74aaf7
ARG ANUBIS_VERSION=v1.27.0-mangyan1.security.1
ARG X_TEXT_VERSION=v0.41.0
ARG GRPC_VERSION=v1.83.2
ARG CEL_GO_VERSION=v0.29.2

RUN apk upgrade --no-cache -a && apk add --no-cache nodejs npm bash brotli zstd git make
WORKDIR /src
RUN git init && git remote add origin https://github.com/TecharoHQ/anubis.git && \
	git fetch --depth 1 origin "$ANUBIS_COMMIT" && git checkout --detach FETCH_HEAD && \
	git fetch --depth 1 origin refs/tags/v1.27.0:refs/tags/v1.27.0 && \
	test "$(git rev-parse HEAD)" = "$ANUBIS_COMMIT" && \
	test "$(git rev-parse 'v1.27.0^{commit}')" = "$ANUBIS_COMMIT"
# Preserve the stable application and generated assets; patch its dependencies.
RUN go get "golang.org/x/text@$X_TEXT_VERSION" "google.golang.org/grpc@$GRPC_VERSION" \
	"github.com/google/cel-go@$CEL_GO_VERSION" && go mod verify
RUN npm ci --ignore-scripts && npm run assets
RUN SKIP_INTEGRATION=1 go test ./... && go vet ./...
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath \
	-ldflags "-s -w -X github.com/TecharoHQ/anubis.Version=$ANUBIS_VERSION" \
	-o /out/anubis ./cmd/anubis

# Keep upstream's non-root user, trust store, data, and runtime entrypoint.
FROM ghcr.io/techarohq/anubis:v1.27.0@sha256:8828275668b7bc675679f100970f9714f731388fbbf66ae94de8aca952e3fc4a
COPY --from=builder /out/anubis /ko-app/anubis
COPY --from=builder /src/LICENSE /licenses/anubis/LICENSE
LABEL org.opencontainers.image.source="https://github.com/mangyan1/NPMplus" \
	org.opencontainers.image.title="Anubis security build for NPMplus" \
	org.opencontainers.image.version="v1.27.0-mangyan1.security.1" \
	org.opencontainers.image.licenses="MIT" \
	io.npmplus.upstream.source="https://github.com/TecharoHQ/anubis" \
	io.npmplus.upstream.revision="d39e26cedcc96bea5e4915297c756e7eec74aaf7"
