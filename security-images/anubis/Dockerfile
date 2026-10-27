# syntax=docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM rust:1.99.0-alpine3.23@sha256:42c2519fdf75d9e34cc61a1aaf34b1a684da9bfd65fe5daefef98d92a801b001 AS rust
RUN rustup target add wasm32-unknown-unknown

FROM golang:1.27.3-alpine3.23@sha256:8a5046497cda39860b832ffdbe8dd66018a0f05bb01352f533a36e7e2ced66a0 AS builder

ARG ANUBIS_COMMIT=a1384fbf42e331652b6f5cc89fdbcdc255d25b8e
ARG ANUBIS_VERSION=v1.28.2-mangyan1.security.1
ARG X_TEXT_VERSION=v0.42.0
ARG X_NET_VERSION=v0.60.0
ARG GRPC_VERSION=v1.84.0
ARG CEL_GO_VERSION=v0.32.0

COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:$PATH
RUN apk upgrade --no-cache -a && apk add --no-cache nodejs npm bash brotli zstd git make gcc musl-dev
WORKDIR /src
RUN git init && git remote add origin https://github.com/TecharoHQ/anubis.git && \
	git fetch --depth 1 origin "$ANUBIS_COMMIT" && git checkout --detach FETCH_HEAD && \
	git fetch --depth 1 origin refs/tags/v1.28.2:refs/tags/v1.28.2 && \
	test "$(git rev-parse HEAD)" = "$ANUBIS_COMMIT" && \
	test "$(git rev-parse 'v1.28.2^{commit}')" = "$ANUBIS_COMMIT"
# Preserve the stable application and generated assets; patch its dependencies.
RUN go get "golang.org/x/text@$X_TEXT_VERSION" "google.golang.org/grpc@$GRPC_VERSION" \
	"cel.dev/cel-go@$CEL_GO_VERSION" "golang.org/x/net@$X_NET_VERSION" && go mod verify
RUN npm ci --ignore-scripts && npm run assets
COPY geoip-fixture.patch /tmp/geoip-fixture.patch
RUN git apply --check /tmp/geoip-fixture.patch && git apply /tmp/geoip-fixture.patch
RUN cargo test --workspace --locked && SKIP_INTEGRATION=1 go test ./... && \
	SKIP_INTEGRATION=1 go test ./lib/geoip -run '^TestUpdate$' -count 100 && go vet ./...
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath \
	-ldflags "-s -w -X github.com/TecharoHQ/anubis.Version=$ANUBIS_VERSION" \
	-o /out/anubis ./cmd/anubis

# Keep upstream's non-root user, trust store, data, and runtime entrypoint.
FROM ghcr.io/techarohq/anubis:v1.28.2@sha256:5fcbce70ee6168be5b226d19bec90111d0acd0daf13028fa06b044cf3ebbbd5f
COPY --from=builder /out/anubis /ko-app/anubis
COPY --from=builder /src/LICENSE /licenses/anubis/LICENSE
LABEL org.opencontainers.image.source="https://github.com/mangyan1/NPMplus" \
	org.opencontainers.image.title="Anubis security build for NPMplus" \
	org.opencontainers.image.version="v1.28.2-mangyan1.security.1" \
	org.opencontainers.image.licenses="MIT" \
	io.npmplus.upstream.source="https://github.com/TecharoHQ/anubis" \
	io.npmplus.upstream.revision="a1384fbf42e331652b6f5cc89fdbcdc255d25b8e"
