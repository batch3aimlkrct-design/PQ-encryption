FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential cmake git python3 python3-venv python3-dev python3-pip libssl-dev libgmp-dev && \
    rm -rf /var/lib/apt/lists/*

# Build liboqs
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    mkdir -p /tmp/liboqs/build && \
    cd /tmp/liboqs && \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON && \
    cmake --build build -j$(nproc) && \
    cmake --install build --prefix /usr/local && \
    rm -rf /tmp/liboqs

WORKDIR /app
COPY . /app
RUN python3 -m venv /opt/venv && . /opt/venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

ENV PATH="/opt/venv/bin:${PATH}"
ENTRYPOINT ["/bin/bash"]