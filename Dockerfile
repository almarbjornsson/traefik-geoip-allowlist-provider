# ───── Build Stage ─────
FROM golang:1.24-alpine AS builder

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy source code
COPY . .

# Build the Go binary (static binary for distroless)
RUN go build -ldflags="-s -w" -o ip-allowlist-service .

# ───── Runtime Stage (Distroless for security) ─────
FROM gcr.io/distroless/static:nonroot

# Copy CA certs and binary from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/ip-allowlist-service /app/ip-allowlist-service

# Create required directory (read/write if needed)
USER nonroot:nonroot

# If your app writes to /data, ensure it exists and is writable
# VOLUME /data

# Set read-only root by default (you can remove this if your app writes logs/files elsewhere)
# Use env vars to configure path if needed
# NOTE: distroless:nonroot already sets WORKDIR to `/`
WORKDIR /

# Expose the port you're serving on (optional, just for docs)
EXPOSE 8123

# Entrypoint
ENTRYPOINT ["/app/ip-allowlist-service"]
