# syntax=docker/dockerfile:1

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web ./
RUN npm run build

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
COPY --from=web /src/internal/api/ui/dist ./internal/api/ui/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

# Alpine rather than distroless: the ping diagnostic needs the iputils ping
# binary, which uses unprivileged ICMP sockets (no root, no capabilities).
FROM alpine:3.22
RUN apk add --no-cache ca-certificates iputils-ping \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app app
COPY --from=build /out/api /usr/local/bin/api
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health >/dev/null || exit 1
# The Go binary is PID 1 and handles SIGTERM itself for graceful shutdown.
ENTRYPOINT ["/usr/local/bin/api"]
