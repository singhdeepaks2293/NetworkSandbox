# --- build stage -----------------------------------------------------------
# Rust 1.89 or newer: the locked `time` crate (pulled in by rcgen) needs 1.88,
# and 1.89 is the oldest toolchain the test suite has been run on. The image
# previously used rust:1.85, which can no longer build the locked dependencies.
FROM rust:1.89-alpine AS build

RUN apk add --no-cache musl-dev gcc
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Static musl binary, size-optimised (see profile.release in Cargo.toml).
# The web UI (src/ui/) is compiled into the binary; nothing else to copy.
RUN cargo build --release --locked

RUN mkdir -p /out/etc/firewall \
    && printf '%s\n' \
       'system hostname firewall' \
       'system cli-port 2200' \
       'system gui-port 8080' \
       'system tls on' \
       'system gui-bind 0.0.0.0' \
       > /out/etc/firewall/firewall.conf

# --- runtime stage ---------------------------------------------------------
FROM scratch

COPY --from=build /src/target/release/firewall /firewall
COPY --from=build /out/etc/firewall /etc/firewall

# 8080 = web GUI (HTTPS), 2200 = CLI. The CLI is plaintext and binds loopback
# inside the container; use `docker exec ... /firewall cli` to reach it.
#
# Userspace dataplane (default). NET_RAW is needed for AF_PACKET and is in
# Docker's default capability set. The daemon refuses to start while kernel
# forwarding is on in its network namespace (the kernel would route traffic
# around the firewall), and a container can start with forwarding enabled,
# so turn it off explicitly:
#
#   docker run -d --name fw \
#     --sysctl net.ipv4.ip_forward=0 \
#     --sysctl net.ipv6.conf.all.forwarding=0 \
#     -e VELA_ADMIN_PASSWORD='choose-a-password' \
#     -p 8443:8080 firewall:latest
#
# Kernel (nftables) dataplane: add `system dataplane kernel` to the config,
# grant NET_ADMIN and turn forwarding ON instead:
#
#   docker run ... --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 ...
#
# Health: GET https://<host>:8080/healthz returns 200 only while the firewall
# is enforcing and 503 when degraded. This scratch image has no HTTP client,
# so there is no Docker HEALTHCHECK; probe it from the orchestrator instead
# (for example a Kubernetes httpGet probe with scheme HTTPS).
#
# containerlab: firewall.clab.yml and firewall-chain.clab.yml already set
# both sysctls for the firewall nodes.
EXPOSE 8080 2200
ENTRYPOINT ["/firewall"]
CMD ["daemon", "--config", "/etc/firewall/firewall.conf"]
