FROM golang:1.23-bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash build-essential ca-certificates curl git wget python3 \
        # cgo build deps (many Go packages use cgo for C bindings)
        libssl-dev zlib1g-dev libsqlite3-dev libffi-dev \
        libxml2-dev libpcre2-dev \
        # Useful for harness subprocess calls
        strace ltrace \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /
