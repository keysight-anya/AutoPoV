FROM mcr.microsoft.com/playwright:v1.52.0-jammy
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-dev \
        curl wget git ca-certificates \
        # For requests/httpx/aiohttp in harness scripts
        libssl-dev libffi-dev \
    && pip3 install --no-cache-dir requests httpx aiohttp \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /
