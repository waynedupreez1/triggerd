FROM docker.io/golang:1.24.5

USER root:root

RUN apt-get -y update
RUN apt-get -y install libpcap-dev iproute2

RUN arch=$(uname -m) && \
    if [ "$arch" = "aarch64" ]; then arch="arm64"; fi && \
    echo "Detected architecture: $arch" && \
    curl -L -o /tmp/xc.tar.gz https://github.com/joerdav/xc/releases/download/v0.8.5/xc_0.8.5_linux_$arch.tar.gz && \
    tar -xzf /tmp/xc.tar.gz -C /usr/local/bin/ && \
    chmod +x /usr/local/bin/xc && \
    xc -complete
