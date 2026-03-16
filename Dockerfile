FROM rust:1.77-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
# Dummy build to cache dependency layer
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

COPY src ./src
# Touch main.rs so cargo sees it as newer than the cached dummy
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

RUN groupadd -r firebreak && useradd -r -g firebreak -s /sbin/nologin firebreak

COPY --from=builder /app/target/release/firebreak /usr/local/bin/firebreak

USER firebreak
EXPOSE 9090
ENV RUST_LOG=firebreak=info

ENTRYPOINT ["firebreak"]
