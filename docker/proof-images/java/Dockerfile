FROM eclipse-temurin:21-jdk-jammy
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash build-essential ca-certificates curl git wget unzip \
        python3 strace ltrace \
        # Native JNI / JNA build deps
        libssl-dev zlib1g-dev libffi-dev libxml2-dev libpq-dev \
        # OpenJDK 11 and 17 for legacy Gradle/Maven compatibility (from apt — reliable)
        openjdk-11-jdk-headless \
        openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Install Maven 3.9.9 (apt maven is 3.8.x, too old for modern plugins)
RUN curl -fsSL https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz \
    | tar -xz -C /opt \
    && ln -s /opt/apache-maven-3.9.9/bin/mvn /usr/local/bin/mvn
ENV MAVEN_HOME=/opt/apache-maven-3.9.9

# Install Gradle 8.7 (system fallback when wrapper is absent)
RUN curl -fsSL https://services.gradle.org/distributions/gradle-8.7-bin.zip -o /tmp/gradle.zip \
    && unzip -d /opt /tmp/gradle.zip \
    && rm /tmp/gradle.zip \
    && ln -s /opt/gradle-8.7/bin/gradle /usr/local/bin/gradle

# Pre-warm Maven local repo with common parent POMs so first-run downloads are faster
RUN mvn -version && mvn dependency:get -Dartifact=org.springframework.boot:spring-boot-starter-parent:3.2.0:pom -q 2>/dev/null || true
RUN mvn dependency:get -Dartifact=org.apache.commons:commons-lang3:3.12.0 -q 2>/dev/null || true
RUN mvn dependency:get -Dartifact=com.fasterxml.jackson.core:jackson-databind:2.15.0 -q 2>/dev/null || true

ENV JAVA_HOME=/opt/java/openjdk
ENV JAVA11_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV JAVA17_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV JAVA21_HOME=/opt/java/openjdk
WORKDIR /
