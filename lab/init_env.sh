#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SAVOP_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAB_DIR="${SAVOP_LAB_DIR:-$SCRIPT_DIR}"

# Install Docker and base system dependencies.
apt-get -y update
apt-get install -y ca-certificates curl gnupg
install -m 755 -d /etc/apt/keyrings
DOCKER_APT_MIRROR="${DOCKER_APT_MIRROR:-https://mirrors.aliyun.com/docker-ce/linux/ubuntu}"
curl -fsSL "$DOCKER_APT_MIRROR/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# shellcheck disable=SC1091
. /etc/os-release
architecture="$(dpkg --print-architecture)"
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] %s %s stable\n' \
  "$architecture" "$DOCKER_APT_MIRROR" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
apt-get -y update
apt-get -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# BIRD build and emulator runtime dependencies.
apt-get -y install   apt-utils   autoconf   bison   build-essential   debhelper   dpkg-dev   expect   flex   git   iptables   iputils-ping   jq   libreadline-dev   libssh-gcrypt-dev   linuxdoc-tools-latex   ncurses-dev   net-tools   opensp   quilt   shellcheck   sqlite3   texlive-latex-extra   traceroute   vim   xsltproc

if ! command -v containerlab >/dev/null 2>&1; then
  CONTAINERLAB_INSTALL_URL="${CONTAINERLAB_INSTALL_URL:-https://get.containerlab.dev}"
  curl -sL "$CONTAINERLAB_INSTALL_URL" | bash
fi

docker build -f "$LAB_DIR/dockerfiles/savop_base" "$LAB_DIR" -t savop_base

# Rust environment and build.
apt-get -y install curl build-essential libssl-dev openssl pkg-config rustfmt rust-clippy
export RUSTUP_DIST_SERVER="${RUSTUP_DIST_SERVER:-https://mirrors.ustc.edu.cn/rust-static}"
export RUSTUP_UPDATE_ROOT="${RUSTUP_UPDATE_ROOT:-https://mirrors.ustc.edu.cn/rust-static/rustup}"
if [ ! -x "$HOME/.cargo/bin/cargo" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck source=/dev/null
source "$HOME/.cargo/env"

if [ -f "$ROOT/Cargo.toml" ]; then
  cd "$ROOT"
  cargo build --release --workspace --bins
fi

bash "$LAB_DIR/build_router.sh"
docker build -f "$LAB_DIR/dockerfiles/savop_runtime_clab" "$LAB_DIR" -t savop_runtime_clab

if [ -d /root/krill ]; then
  cd /root/krill
  cargo build --features aspa --locked
fi
