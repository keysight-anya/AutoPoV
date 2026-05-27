FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
# Use faster mirror for WSL (default archive.ubuntu.com is unreliable in WSL)
RUN sed -i 's|http://archive.ubuntu.com|http://mirrors.edge.kernel.org|g' /etc/apt/sources.list.d/ubuntu.sources \
    && sed -i 's|http://security.ubuntu.com|http://mirrors.edge.kernel.org|g' /etc/apt/sources.list.d/ubuntu.sources
RUN for i in 1 2 3; do apt-get update && break || sleep 10; done \
    && apt-get dist-upgrade -y \
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
        libasan8 libubsan1 libclang-rt-dev \
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
        # Lexer/parser generators (needed by libpcap, flex-based repos)
        flex bison \
        # Terminal/UI libraries (needed by w3m, ncurses-based repos)
        libncurses5-dev libncursesw5-dev \
        # Boost (needed by muduo and other C++ framework repos)
        libboost-dev libboost-system-dev libboost-thread-dev \
        # Packet capture (needed by libpcap-based repos)
        libpcap-dev \
        # Unit-test frameworks
        check libcunit1-dev libcmocka-dev \
        # Diagnostics
        valgrind strace ltrace \
        # Runtime dep resolver
        apt-file \
    && apt-file update \
    && pip3 install --no-cache-dir --break-system-packages conan \
    && pip3 install --no-cache-dir --break-system-packages \
        requests urllib3 httpx aiohttp \
        flask fastapi uvicorn \
        pyyaml lxml pycparser \
        pexpect psutil paramiko \
        beautifulsoup4 html5lib \
    && rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"
WORKDIR /
