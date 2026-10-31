FROM rust:1-alpine AS build
WORKDIR /src
RUN apk add --no-cache musl-dev
COPY . .
RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:3.20
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/tproxy-server /tproxy-server
