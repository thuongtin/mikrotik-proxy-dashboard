# Every base image is pinned to a version AND a digest so a rebuild cannot
# silently pick up different code. To upgrade: change the tag, then refresh the
# digest with `docker buildx imagetools inspect <image>:<tag>` and rerun
# scripts/build-arm64-tar.sh (it runs vet, tests and govulncheck first).
ARG GO_IMAGE=golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280
ARG SINGBOX_IMAGE=ghcr.io/sagernet/sing-box:v1.14.4@sha256:0788ffbddab2c68a99a2dd4780bbc50902f159af6f589df3ee74a8389d278279
ARG RUNTIME_IMAGE=alpine:3.21.10@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab

# Official sing-box release image, used only as a source for the binary
FROM ${SINGBOX_IMAGE} AS singbox

# Source tree with dependencies, shared by the check and build stages
FROM ${GO_IMAGE} AS source

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Check stage: vet, tests (they call the pinned sing-box binary) and a
# vulnerability scan with the same toolchain that builds the release binary.
# Not part of the final image; build it with `--target check`.
FROM source AS check
ARG GOVULNCHECK_VERSION=v1.10.0
ARG SKIP_VULNCHECK=0
# Go build tags of the edition (see scripts/build-arm64-tar.sh); empty for
# the default build.
ARG GO_BUILD_TAGS=""
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
RUN CGO_ENABLED=0 go vet -tags "$GO_BUILD_TAGS" ./... && \
    CGO_ENABLED=0 go test -tags "$GO_BUILD_TAGS" ./...
RUN if [ "$SKIP_VULNCHECK" = "1" ]; then \
        echo "WARNING: SKIP_VULNCHECK=1, govulncheck skipped" >&2; \
    else \
        go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" -tags "$GO_BUILD_TAGS" ./...; \
    fi

# Stage 1: Build Go static binary and compress binaries
FROM source AS builder
ARG GO_BUILD_TAGS=""

RUN apk add --no-cache upx

# Build for linux/arm64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags "$GO_BUILD_TAGS" -trimpath -ldflags="-s -w" -o /app/proxy-dash .
RUN upx -9 /app/proxy-dash || true

# Copy and compress official sing-box binary
COPY --from=singbox /usr/local/bin/sing-box /app/sing-box
RUN upx -9 /app/sing-box || true

# Stage 2: Minimal ARM64 runtime image
FROM ${RUNTIME_IMAGE}
# Extra Alpine packages an edition needs at runtime; empty by default.
ARG EXTRA_APK_PACKAGES=""

# Install runtime networking utilities and certificates.
# iptables (nft backend) and iptables-legacy are both needed: entrypoint.sh
# tries each one for the forward guard, depending on what the kernel offers.
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    iproute2 \
    iptables \
    iptables-legacy \
    $EXTRA_APK_PACKAGES \
    && rm -rf /var/cache/apk/*

# Copy compressed binaries
COPY --chmod=755 --from=builder /app/sing-box /usr/local/bin/sing-box
COPY --chmod=755 --from=builder /app/proxy-dash /usr/local/bin/proxy-dash

# Copy entrypoint script with executable permissions
COPY --chmod=755 entrypoint.sh /entrypoint.sh

# Environment and volumes
ENV LISTEN_ADDR=":8080" \
    DATA_DIR="/data" \
    LAN_CIDR="10.88.88.0/24" \
    CONTAINER_GW="10.10.10.1" \
    SINGBOX_PATH="/usr/local/bin/sing-box" \
    FORWARD_GUARD="auto"

VOLUME ["/data"]
EXPOSE 8080 53/udp 53/tcp

# entrypoint.sh stays PID 1: it traps SIGTERM (RouterOS kills a PID 1 that
# does not catch it, without waiting for stop-time), forwards it to proxy-dash
# and reaps orphaned processes. Do not put tini in front of it.
ENTRYPOINT ["/entrypoint.sh"]
