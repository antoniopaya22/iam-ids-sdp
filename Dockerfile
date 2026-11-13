# syntax=docker/dockerfile:1
# One build, three runtime images (compose selects them with `target:`):
#   controller : sdp-controller + sdp-pki (PKI bootstrap) + fwknop-server, iptables
#   gateway    : sdp-gateway + fwknop-server, iptables, conntrack
#   client     : sdp-client + fwknop-client, curl, hey (load testing), jq
# The IDS has its own image (ids/Dockerfile).

FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/ ./cmd/...

# Controller and gateway own the firewall and run fwknopd (libpcap): they run as root
# with NET_ADMIN and NET_RAW only (see docker-compose.yml).
FROM debian:bookworm-slim AS firewalled
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates fwknop-server iptables conntrack iproute2 procps \
 && rm -rf /var/lib/apt/lists/*

FROM firewalled AS controller
COPY --from=build /out/sdp-controller /out/sdp-pki /usr/local/bin/
COPY lab/pki-bootstrap.sh /usr/local/bin/pki-bootstrap.sh
ENTRYPOINT ["sdp-controller"]
CMD ["serve"]

FROM firewalled AS gateway
COPY --from=build /out/sdp-gateway /usr/local/bin/
ENTRYPOINT ["sdp-gateway"]
CMD ["serve"]

FROM debian:bookworm-slim AS client
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates fwknop-client curl hey jq iproute2 procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --home-dir /home/sdp --shell /bin/bash sdp
COPY --from=build /out/sdp-client /usr/local/bin/
USER 10001
WORKDIR /home/sdp
CMD ["sleep", "infinity"]
