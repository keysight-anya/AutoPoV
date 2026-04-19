FROM ruby:3.3-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash build-essential ca-certificates curl git wget python3 \
        # Native gem build deps (nokogiri, pg, mysql2, sqlite3, etc.)
        libssl-dev zlib1g-dev libbz2-dev libffi-dev libreadline-dev \
        libsqlite3-dev libpq-dev libxml2-dev libxslt1-dev \
        libjpeg-dev libpng-dev \
        # Useful for harness subprocess calls
        strace ltrace \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /
