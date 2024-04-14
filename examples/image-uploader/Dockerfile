# docker build -f examples/image-uploader/Dockerfile .
FROM rust:1.77-alpine as builder

WORKDIR /usr/src/app
RUN apk update && apk add --no-cache musl-dev
COPY . .
WORKDIR /usr/src/app/examples/image-uploader
RUN cargo install --locked --path . --target=x86_64-unknown-linux-musl

FROM scratch
ENV PORT=8080
COPY --from=builder /usr/local/cargo/bin/image-uploader /usr/local/bin/image-uploader
ENTRYPOINT ["image-uploader"]
