# Multi-stage build: the compiler image is ~1.5GB, the runtime image ~25MB.
# 1.94 is the floor set by sqlx-postgres 0.9; bump deliberately, not to :latest.
FROM rust:1.94-alpine AS build
# upgrade picks up security patches newer than the base image; --no-cache
# leaves no apk cache behind, so no separate clean step is needed.
RUN apk upgrade --no-cache && apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release

FROM alpine:3.22
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=build /build/target/release/openberat /usr/local/bin/openberat
USER nobody
EXPOSE 8081
CMD ["openberat"]
