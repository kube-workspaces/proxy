FROM golang:1.26-alpine AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -o kube-workspaces-proxy ./cmd/proxy/

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/kube-workspaces-proxy .
USER 65532:65532

ENTRYPOINT ["/kube-workspaces-proxy"]
CMD ["--port", "8080"]
