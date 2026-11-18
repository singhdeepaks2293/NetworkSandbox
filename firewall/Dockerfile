# --- build stage -----------------------------------------------------------
FROM rust:1.85-alpine AS build

RUN apk add --no-cache musl-dev gcc
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Static musl binary, size-optimised (see profile.release in Cargo.toml).
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

# 8080 = web GUI, 2200 = CLI. NET_RAW is required for the AF_PACKET dataplane;
# it is part of Docker's default capability set and containerlab runs nodes
# privileged, so no extra setting is needed there.
EXPOSE 8080 2200
ENTRYPOINT ["/firewall"]
CMD ["daemon", "--config", "/etc/firewall/firewall.conf"]
