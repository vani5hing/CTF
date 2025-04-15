FROM ubuntu:20.04

# Set environment variables to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update and install necessary development tools (excluding gdb)
RUN apt-get update && apt-get install -y \
    build-essential \
    nano \
    wget \
    curl \
    vim \
    git \
    net-tools \
    iputils-ping \
    python3 \
    python3-pip \
    manpages-dev \
    && rm -rf /var/lib/apt/lists/*

# Verify glibc version
RUN ldd --version

# Set working directory
WORKDIR /workspace

# Keep container running
CMD ["/bin/bash"]
