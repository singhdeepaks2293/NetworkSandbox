# --- build stage -----------------------------------------------------------
FROM rust:1.75-alpine AS build

RUN apk add --no-cache musl-dev gcc
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Static musl binary, size-optimised (see profile.release in Cargo.toml).
RUN cargo build --release --locked

RUN mkdir -p /out/etc/firewall
COPY examples/default.conf /out/etc/firewall/firewall.conf

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
