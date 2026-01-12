FROM golang:1.25.5-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    clang \
    llvm \
    libbpf-dev \
    linux-headers \
    make \
    git

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/http-tracer ./cmd/tracer

# Final image
FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/bin/http-tracer /usr/local/bin/http-tracer

ENTRYPOINT ["/usr/local/bin/http-tracer"]

