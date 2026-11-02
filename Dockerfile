# cleanreach CLI as a container: scheduled list-cleaning on any server.
FROM rust:1-alpine AS build
WORKDIR /src
COPY Cargo.toml ./
COPY core ./core
COPY cli ./cli
RUN cargo build --release --bin cleanreach

FROM alpine:3.20
RUN adduser -D cleanreach
COPY --from=build /src/target/release/cleanreach /usr/local/bin/cleanreach
USER cleanreach
ENTRYPOINT ["cleanreach"]
CMD ["help"]
