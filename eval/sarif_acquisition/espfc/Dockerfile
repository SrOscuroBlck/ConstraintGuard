FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang \
    clang-tools \
    clang-tidy \
    cmake \
    make \
    git \
    python3 \
    python3-pip \
    curl \
    wget \
    unzip \
    libusb-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install PlatformIO
RUN pip3 install platformio

# Pin esp-fc commit for reproducibility
# Using a stable release of esp-fc (ESP32 flight controller)
RUN git clone --depth=1 https://github.com/rtlopez/esp-fc.git /src/espfc

WORKDIR /src/espfc

# Pre-fetch ESP32 platform + framework (slow, ~500MB)
RUN pio pkg install --environment esp32dev 2>&1 | tail -20 || \
    pio platform install espressif32 2>&1 | tail -10 || true

COPY run_scan.sh /run_scan.sh
RUN chmod +x /run_scan.sh

CMD ["/run_scan.sh"]
