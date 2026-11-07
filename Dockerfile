# syntax=docker/dockerfile:1
FROM docker.io/library/rust:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    mingw-w64 \
    binutils-mingw-w64 \
    gcc-mingw-w64-x86-64 \
    zip \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-pc-windows-gnu
RUN rustup component add clippy rustfmt

ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc

WORKDIR /workspace
