FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        # Core build toolchain
        bash build-essential clang clang-tools clang-format lld llvm \
        cmake ninja-build meson gdb git curl wget ca-certificates \
        pkg-config autoconf automake libtool m4 autogen \
        # Python (for PoV scripts + meson + conan)
        python3 python3-pip python3-dev python3-setuptools python3-wheel \
        # Node / JS
        nodejs npm \
        # Ruby
        ruby-full ruby-dev \
        # PHP
        php-cli php-dev \
        # Go
        golang-go \
        # Java
        openjdk-21-jdk-headless \
        # Rust (cargo)
        cargo rustc \
        # ASan / UBSan — shared runtime + static linker libs (needed by CMake compiler test)
        libasan6 libubsan1 libclang-rt-dev \
        # Common C/C++ library deps (covers most open-source C repos)
        libssl-dev zlib1g-dev libpcre3-dev libpcre2-dev \
        libevent-dev libuv1-dev libev-dev \
        libbz2-dev liblz4-dev libzstd-dev libsnappy-dev \
        libjpeg-dev libpng-dev libtiff-dev libwebp-dev \
        libsqlite3-dev libpq-dev default-libmysqlclient-dev \
        libcurl4-openssl-dev libxml2-dev libxslt1-dev libsodium-dev \
        libprotobuf-dev protobuf-compiler \
        libgmp-dev libgcrypt20-dev \
        libffi-dev libreadline-dev \
        libjpeg-turbo8-dev \
        # Unit-test frameworks
        check libcunit1-dev libcmocka-dev \
        # Diagnostics
        valgrind strace ltrace \
        # Runtime dep resolver
        apt-file \
    && apt-file update \
    && pip3 install --no-cache-dir --break-system-packages conan \
    && pip3 install --no-cache-dir --break-system-packages \
        requests urllib3 httpx \
        flask fastapi uvicorn \
        pyyaml lxml pycparser \
    && rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"
WORKDIR /
