FROM docker.io/rustlang/rust:nightly AS build

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --create-home --home /var/lib/leaf --shell /usr/sbin/nologin leaf

COPY --from=build /app/target/release/leaf /usr/local/bin/leaf

USER 10001:10001
WORKDIR /var/lib/leaf

EXPOSE 5300/udp
EXPOSE 5300/tcp

ENTRYPOINT ["/usr/local/bin/leaf"]
