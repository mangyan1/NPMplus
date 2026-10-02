# syntax=docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM golang:1.26.8-alpine3.23@sha256:33ce311e5eecedee48ec1b84419c1306e9fbd71009f0d5c3f2a6904b579c1ecc AS builder

ARG CROWDSEC_COMMIT=909b5157986a2b2c2163300fdaef5ed01289f7d2
ARG RE2_COMMIT=241e2e430836e80f93d704d1f06cd3e7fe3100f5
ARG GRPC_VERSION=v1.83.2
ARG X_CRYPTO_VERSION=v0.56.0
ARG PGX_VERSION=v5.11.0
ARG YQ_VERSION=v4.50.1
ARG X_NET_VERSION=v0.58.0
ARG X_TEXT_VERSION=v0.41.0
ENV CGO_CFLAGS=-D_LARGEFILE64_SOURCE

RUN apk upgrade --no-cache -a && apk add --no-cache git g++ gcc libc-dev make bash gettext binutils-gold coreutils pkgconfig
# Preserve upstream's native RE2 and static SQLite build, including every plugin.
RUN git init /re2 && git -C /re2 remote add origin https://github.com/google/re2.git && \
	git -C /re2 fetch --depth 1 origin "$RE2_COMMIT" && git -C /re2 checkout --detach FETCH_HEAD && \
	test "$(git -C /re2 rev-parse HEAD)" = "$(git -C /re2 rev-parse "$RE2_COMMIT^{commit}")" && make -C /re2 -j2 install
WORKDIR /src
RUN git init && git remote add origin https://github.com/crowdsecurity/crowdsec.git && \
	git fetch --depth 1 origin "$CROWDSEC_COMMIT" && git checkout --detach FETCH_HEAD && \
	git fetch --depth 1 origin refs/tags/v1.8.1:refs/tags/v1.8.1 && \
	test "$(git rev-parse HEAD)" = "$CROWDSEC_COMMIT" && \
	test "$(git rev-parse 'v1.8.1^{commit}')" = "$CROWDSEC_COMMIT"
COPY postgres-v5.patch /tmp/postgres-v5.patch
COPY parser-security_test.go pkg/database/parser_security_test.go
RUN git apply /tmp/postgres-v5.patch && go mod edit -droprequire github.com/jackc/pgx/v4 && \
	go get "google.golang.org/grpc@$GRPC_VERSION" "golang.org/x/crypto@$X_CRYPTO_VERSION" \
	"github.com/jackc/pgx/v5@$PGX_VERSION" && go mod tidy && go mod verify
RUN TEST_LOCAL_ONLY=1 go test -timeout 3m \
	-tags netgo,osusergo,expr_debug,nomsgpack,sqlite_omit_load_extension,re2_cgo \
	./pkg/database/... ./pkg/apiserver/... ./pkg/appsec/... ./pkg/exprhelpers/... ./pkg/csconfig/... ./pkg/hubtest/...
RUN go list -deps -tags netgo,osusergo,expr_debug,nomsgpack,sqlite_omit_load_extension,re2_cgo ./cmd/... > /tmp/dependencies && \
	if grep -F 'golang.org/x/crypto/openpgp' /tmp/dependencies; then exit 1; fi
# The entrypoint's yq is a separate Go executable and needs its own patched graph.
WORKDIR /tools/yq
RUN go mod init npmplus.tools/yq && go get "github.com/mikefarah/yq/v4@$YQ_VERSION" \
	"golang.org/x/net@$X_NET_VERSION" "golang.org/x/text@$X_TEXT_VERSION" && \
	CGO_ENABLED=0 go build -mod=readonly -trimpath -o /out/yq github.com/mikefarah/yq/v4
WORKDIR /src
RUN make -j2 build BUILD_VERSION=v1.8.1 BUILD_TAG=909b515-mangyan1.security.1 \
	BUILD_TIMESTAMP=2026-10-02T00:00:00Z DOCKER_BUILD=1 BUILD_STATIC=1 && \
	mkdir -p /out/plugins && cp cmd/crowdsec/crowdsec cmd/crowdsec-cli/cscli /out/ && \
	find cmd -name 'notification-*' -type f -executable -exec cp '{}' /out/plugins/ \;

FROM docker.io/crowdsecurity/crowdsec:latest@sha256:0f2523fa61ef507f15d953045cface490cc880670c62f2755ced17524107f71a
RUN apk upgrade --no-cache -a
COPY --from=builder /out/crowdsec /out/cscli /usr/local/bin/
COPY --from=builder /out/yq /usr/local/bin/yq
COPY --from=builder /out/plugins/ /usr/local/lib/crowdsec/plugins/
COPY --from=builder /src/LICENSE /licenses/crowdsec/LICENSE
LABEL org.opencontainers.image.source="https://github.com/mangyan1/NPMplus" \
	org.opencontainers.image.title="CrowdSec security build for NPMplus" \
	org.opencontainers.image.version="v1.8.1-mangyan1.security.1" \
	org.opencontainers.image.licenses="MIT" \
	io.npmplus.upstream.source="https://github.com/crowdsecurity/crowdsec" \
	io.npmplus.upstream.revision="909b5157986a2b2c2163300fdaef5ed01289f7d2"
