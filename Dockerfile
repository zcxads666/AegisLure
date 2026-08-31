FROM golang:1.26-alpine AS build

WORKDIR /src
ARG TARGETOS=linux
ARG TARGETARCH
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/aegislure ./cmd/aegislure \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/hpctl ./cmd/hpctl

FROM alpine:3.21
RUN addgroup -S -g 10001 aegislure && adduser -S -D -H -u 10001 -G aegislure aegislure
COPY --from=build /out/aegislure /usr/local/bin/aegislure
COPY --from=build /out/hpctl /usr/local/bin/hpctl
USER 10001:10001
WORKDIR /var/lib/aegislure
ENTRYPOINT ["/usr/local/bin/aegislure", "-config", "/var/lib/aegislure/config.json"]
