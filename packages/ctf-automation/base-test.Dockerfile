# Base Test Image for Tool Learning
# This image is built once and cached for all tool installation tests
# Provides common prerequisites to speed up testing

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install common prerequisites for most tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # Version control
    git \
    # Package managers
    python3 \
    python3-pip \
    ruby \
    ruby-dev \
    gem \
    # Build tools
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    # Common utilities
    curl \
    wget \
    unzip \
    tar \
    gzip \
    # Network tools
    net-tools \
    iputils-ping \
    # Security
    ca-certificates \
    gnupg \
    # Libraries commonly needed
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Pre-configure pip to avoid warnings
RUN pip3 config set global.break-system-packages true

# Create common directories
RUN mkdir -p /opt /tools /workspace

# Set working directory
WORKDIR /workspace

# Label for identification
LABEL purpose="tool-learning-base" \
      version="1.0" \
      maintained-by="ctf-automation"
