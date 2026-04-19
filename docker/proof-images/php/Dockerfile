FROM php:8.3-cli
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash build-essential ca-certificates curl git wget python3 unzip \
        # PHP extension build deps (gd, xml, zip, mbstring, pdo, etc.)
        libssl-dev zlib1g-dev libbz2-dev libffi-dev \
        libxml2-dev libxslt1-dev \
        libjpeg-dev libpng-dev libwebp-dev \
        libsqlite3-dev libpq-dev \
        libzip-dev libonig-dev \
        # Composer
    && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /
