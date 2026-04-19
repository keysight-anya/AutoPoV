FROM python:3.12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash build-essential ca-certificates curl git wget \
        # C extension build deps (many Python packages compile C extensions)
        libssl-dev zlib1g-dev libbz2-dev libffi-dev libreadline-dev \
        libsqlite3-dev libxml2-dev libxslt1-dev libjpeg-dev libpng-dev \
        # Useful for harness subprocess calls
        strace ltrace \
    && rm -rf /var/lib/apt/lists/*
# GAP-4: Pre-install common PoV runtime packages so scripts that import
# requests/flask/etc. don't need to pip-install at runtime.
RUN pip3 install --no-cache-dir \
    requests urllib3 httpx \
    flask fastapi uvicorn gunicorn \
    django cherrypy tornado aiohttp bottle \
    pytest pyyaml lxml beautifulsoup4 \
    paramiko cryptography pycparser
WORKDIR /
