FROM eclipse-temurin:21-jdk-noble
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash build-essential ca-certificates curl git wget unzip \
        maven \
        python3 \
        # Native JNI / JNA build deps
        libssl-dev zlib1g-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*
# Install Gradle 8.7
RUN curl -fsSL https://services.gradle.org/distributions/gradle-8.7-bin.zip -o /tmp/gradle.zip \
    && unzip -d /opt /tmp/gradle.zip \
    && rm /tmp/gradle.zip \
    && ln -s /opt/gradle-8.7/bin/gradle /usr/local/bin/gradle
WORKDIR /
