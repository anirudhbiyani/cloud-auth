# Verifier image for the cloud-auth integration harness.
#
# Build from the REPOSITORY ROOT (the whole module is the build context):
#
#   docker build -f test/harness/verifier/Dockerfile -t "$IMAGE" .
#   docker push "$IMAGE"
#
# The result is a static, non-root, ~10MB image with no shell: the verifier
# handles cloud identity, so the smallest possible attack surface is the point.

FROM golang:1.26 AS build
WORKDIR /src

# Dependencies first so a source-only change reuses the module cache layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 for a fully static binary (distroless/static has no libc).
# -trimpath and -ldflags "-s -w" drop local paths and symbol tables.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/verifier ./test/harness/verifier

# distroless/static carries ca-certificates (needed for every STS endpoint) and
# nothing else — no shell, no package manager.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/verifier /usr/local/bin/verifier

# 65532 is distroless' "nonroot" user.
USER 65532:65532
WORKDIR /work

# targets.json is delivered by the driver: mounted at /etc/cloud-auth/targets.json
# (ConfigMap) or inlined in $CLOUD_AUTH_TARGETS_JSON.
ENV CLOUD_AUTH_TARGETS_FILE=/etc/cloud-auth/targets.json

ENTRYPOINT ["/usr/local/bin/verifier"]
