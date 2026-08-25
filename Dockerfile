# --platform=$BUILDPLATFORM keeps the toolchain running natively; the target
# architecture is passed to the compiler instead. Without this, a multi-arch
# build emulates the whole Go compile under QEMU, which is an order of magnitude
# slower and occasionally flaky.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

# Build information, surfaced by --version, the startup log and /version.
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -a -ldflags "\
      -X main.version=${VERSION} \
      -X main.commit=${COMMIT} \
      -X main.buildDate=${BUILD_DATE}" \
    -o kube-workspaces-proxy ./cmd/proxy/

FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source="https://github.com/kube-workspaces/proxy"
WORKDIR /
COPY --from=builder /workspace/kube-workspaces-proxy .
USER 65532:65532

ENTRYPOINT ["/kube-workspaces-proxy"]
CMD ["--port", "8080"]
