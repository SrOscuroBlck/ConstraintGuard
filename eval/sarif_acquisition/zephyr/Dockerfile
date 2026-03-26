FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang \
    clang-tools \
    clang-tidy \
    cmake \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Clone just the Zephyr kernel repo (no west workspace, no SDK needed for static analysis)
RUN git clone --depth=1 https://github.com/zephyrproject-rtos/zephyr.git /src/zephyr

WORKDIR /src/zephyr

RUN pip3 install --quiet openai anthropic

COPY zephyr/run_scan.sh /run_scan.sh
COPY discover.py /discover.py
RUN chmod +x /run_scan.sh

CMD ["/run_scan.sh"]
