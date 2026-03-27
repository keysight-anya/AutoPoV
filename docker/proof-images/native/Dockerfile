FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update     && apt-get install -y --no-install-recommends        bash build-essential clang cmake ninja-build meson gdb git curl ca-certificates        python3 python3-pip nodejs npm ruby-full php-cli golang-go pkg-config     && rm -rf /var/lib/apt/lists/*
WORKDIR /
