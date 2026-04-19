FROM node:22-bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash build-essential ca-certificates curl git wget python3 \
        # Native addon build deps (node-gyp, canvas, sharp, etc.)
        libssl-dev zlib1g-dev libjpeg-dev libpng-dev libwebp-dev \
        libxml2-dev libxslt1-dev libffi-dev \
        # Useful for harness subprocess calls
        strace ltrace \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /
