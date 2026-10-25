# --- build stage -----------------------------------------------------------
FROM rust:1.75-alpine AS build

RUN apk add --no-cache musl-dev gcc
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Static musl binary, size-optimised (see profile.release in Cargo.toml).
RUN cargo build --release --locked

# Directories the daemon expects in the runtime image.
RUN mkdir -p /out/etc/switch /out/run/switch

# --- runtime stage ---------------------------------------------------------
FROM scratch

COPY --from=build /src/target/release/switch /switch
COPY --from=build /out/etc/switch /etc/switch
COPY --from=build /out/run/switch /run/switch
EXPOSE 2200
# NET_RAW is required for AF_PACKET sockets. It is part of Docker's default
# capability set, but rootless/restricted runtimes may need --cap-add=NET_RAW.
# Containerlab runs its nodes privileged, so no extra setting is needed there.
ENTRYPOINT ["/switch"]
CMD ["daemon", "--tcp", "2200"]
