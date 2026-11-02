FROM rust:1.94.1-alpine AS builder

RUN apk add --no-cache build-base
WORKDIR /app
COPY . .
RUN cargo build --locked --release -p sekisho --bin sekisho

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && addgroup -S sekisho \
    && adduser -S -G sekisho -h /data sekisho \
    && mkdir -p /data \
    && chown sekisho:sekisho /data

COPY --from=builder /app/target/release/sekisho /usr/local/bin/sekisho
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint

USER sekisho
ENV HOME=/data
ENV SEKISHO_HOME=/data/.sekisho
VOLUME ["/data"]
EXPOSE 7470
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
