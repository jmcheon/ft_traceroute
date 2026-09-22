#!/bin/bash
# One-shot provisioning for the ft_traceroute Debian VM.
# Creates the user, grants sudo, installs everything needed to build and test.
# Idempotent: safe to re-run any time.
#
# Local QEMU VM:  run as root ->  bash provision.sh
# Vagrant:        run automatically by the Vagrantfile (provision "shell")
set -e

USERNAME="cjung-mo"
DEFAULT_PASS="42"   # change after first login: passwd

export DEBIAN_FRONTEND=noninteractive

echo "==> apt packages"
apt-get update
apt-get install -y \
    sudo \
    build-essential \
    gdb \
    git \
    rsync \
    openssh-server \
    inetutils-ping \
    traceroute \
    tcpdump \
    manpages-dev \
    man-db

echo "==> user $USERNAME"
if ! id "$USERNAME" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$USERNAME"
    echo "$USERNAME:$DEFAULT_PASS" | chpasswd
    echo "    created (password: $DEFAULT_PASS — change it with passwd)"
else
    echo "    already exists, skipping creation"
fi
usermod -aG sudo "$USERNAME"

echo "==> sshd"
systemctl enable --now ssh

echo "==> sanity check"
traceroute --version | head -1   # reference traceroute for comparison
cc --version | head -1

echo "==> done. Log in as $USERNAME and build with: make re"
