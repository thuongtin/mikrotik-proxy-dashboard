# Stage 1: Build Go static binary and compress binaries
FROM golang:alpine AS builder

RUN apk add --no-cache upx

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build for linux/arm64
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /app/proxy-dash .
RUN upx -9 /app/proxy-dash || true

# Copy and compress official sing-box binary
COPY --from=ghcr.io/sagernet/sing-box:latest /usr/local/bin/sing-box /app/sing-box
RUN upx -9 /app/sing-box || true

# Stage 2: Minimal ARM64 runtime image
FROM alpine:3.21

# Install runtime networking utilities and certificates
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    iproute2 \
    iptables \
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
    SINGBOX_PATH="/usr/local/bin/sing-box"

VOLUME ["/data"]
EXPOSE 8080 53/udp 53/tcp

ENTRYPOINT ["/entrypoint.sh"]
