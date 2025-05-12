# First stage: build environment
FROM --platform=$BUILDPLATFORM golang:1.24.1 AS builder
ARG TARGETARCH
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -o tokenetes ./cmd

# Second stage: runtime environment
FROM --platform=$TARGETPLATFORM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/tokenetes .

LABEL org.opencontainers.image.source=https://github.com/tokenetes/tokenetes
LABEL org.opencontainers.image.description="Tokenetes - Transaction Tokens Service"
LABEL org.opencontainers.image.licenses=Apache

ENTRYPOINT ["./tokenetes"]