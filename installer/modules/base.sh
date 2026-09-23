#!/usr/bin/env bash

set -euo pipefail

echo "[AthenaSec] Installing base dependencies..."

sudo apt update

sudo apt install -y \
  curl \
  wget \
  git \
  unzip \
  zip \
  ca-certificates \
  gnupg \
  lsb-release \
  build-essential \
  python3 \
  python3-venv \
  python3-pip \
  openssh-server

#
# Node.js
#

echo "[AthenaSec] Checking Node.js and npm..."

NODE_REQUIRED_MAJOR=22
NODE_CURRENT_MAJOR=0

if command -v node >/dev/null 2>&1; then
  NODE_CURRENT_MAJOR="$(node --version | sed 's/^v//' | cut -d. -f1)"
fi

if [ "$NODE_CURRENT_MAJOR" -lt "$NODE_REQUIRED_MAJOR" ]; then
  echo "[AthenaSec] Installing Node.js 22..."

  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt install -y nodejs
fi

if ! command -v node >/dev/null 2>&1; then
  echo "[AthenaSec] ERROR: Node.js installation failed."
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "[AthenaSec] ERROR: npm is missing."
  exit 1
fi

echo "[AthenaSec] Node.js: $(node --version)"
echo "[AthenaSec] npm: $(npm --version)"

#
# Docker
#

echo "[AthenaSec] Checking Docker..."

if ! command -v docker >/dev/null 2>&1; then
  echo "[AthenaSec] Installing Docker..."

  sudo install -m 0755 -d /etc/apt/keyrings

  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg

  sudo chmod a+r /etc/apt/keyrings/docker.gpg

  ARCH="$(dpkg --print-architecture)"
  CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"

  echo \
    "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

  sudo apt update

  sudo apt install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[AthenaSec] ERROR: Docker installation failed."
  exit 1
fi

echo "[AthenaSec] Enabling Docker..."

sudo systemctl enable docker
sudo systemctl start docker

if ! sudo systemctl is-active --quiet docker; then
  echo "[AthenaSec] ERROR: Docker service is not running."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "[AthenaSec] ERROR: Docker Compose plugin is missing."
  exit 1
fi

echo "[AthenaSec] Docker: $(docker --version)"
echo "[AthenaSec] Docker Compose: $(docker compose version --short)"
echo "[AthenaSec] Docker service: running"

#
# AthenaSec directories
#

echo "[AthenaSec] Creating base directories..."

sudo mkdir -p /opt/athenasec
sudo mkdir -p /var/lib/athenasec
sudo mkdir -p /var/log/athenasec

echo "[AthenaSec] Base setup complete."
