ARG TARGET=buster

FROM rust:1-$TARGET as builder

WORKDIR /code
COPY . .
RUN cargo build --release

FROM debian:$TARGET-slim

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /code/target/release/acmed /usr/local/bin/acmed
COPY --from=builder /code/target/release/tacd  /usr/local/bin/tacd
CMD ["/usr/local/bin/acmed", "-f", "--log-stderr"]