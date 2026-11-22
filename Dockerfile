FROM rust:latest AS rust-builder
WORKDIR /src
COPY rust/ rust/
RUN cargo build --release --manifest-path rust/Cargo.toml

FROM golang:1.23 AS go-builder
WORKDIR /src
COPY go/ go/
COPY rust/include/ rust/include/
COPY --from=rust-builder /src/rust/target/release/libkeygate_policy.so /src/rust/target/release/
RUN cd go && CGO_ENABLED=1 go build -o /usr/local/bin/keygate ./cmd/gateway

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=rust-builder /src/rust/target/release/libkeygate_policy.so /src/rust/target/release/
COPY --from=go-builder /usr/local/bin/keygate /usr/local/bin/keygate
COPY config/keygate.conf /etc/keygate/keygate.conf
EXPOSE 8080
ENTRYPOINT ["keygate", "-config", "/etc/keygate/keygate.conf"]
