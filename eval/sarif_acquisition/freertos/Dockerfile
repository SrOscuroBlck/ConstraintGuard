FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang \
    clang-tools \
    clang-tidy \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    cmake \
    make \
    git \
    python3 \
    python3-pip \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/FreeRTOS/FreeRTOS-Kernel.git /src/freertos

WORKDIR /src/freertos

# Provide a minimal FreeRTOSConfig.h so clang-analyzer-* can process core kernel files
COPY FreeRTOSConfig.h /src/freertos/include/FreeRTOSConfig.h

COPY run_scan.sh /run_scan.sh
RUN chmod +x /run_scan.sh

CMD ["/run_scan.sh"]
