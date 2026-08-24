FROM docker.io/library/rust:1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang libclang-dev pkg-config cmake libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
