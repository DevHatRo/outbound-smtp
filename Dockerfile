# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/outbound-smtp ./cmd/outbound-smtp

FROM alpine:3.24
# ca-certificates: verify the smarthost certificate. tzdata: local time in logs if TZ is set.
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 10001 -s /sbin/nologin relay \
    && mkdir /data && chown relay:relay /data && chmod 700 /data
COPY --from=build /out/outbound-smtp /usr/local/bin/outbound-smtp
USER 10001:10001
ENV DATA_DIR=/data
VOLUME /data
# 465 and 587 always; 25 only with SMTP_ENABLE_PORT25=true; 9090 is /metrics, keep it private.
EXPOSE 465 587 25 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/usr/local/bin/outbound-smtp", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/outbound-smtp"]
CMD ["serve"]
