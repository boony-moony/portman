#!/bin/bash
# portman installer — run as root on your Linode
set -e

# ── 1. Dependencies ───────────────────────────────────────────────────────────
echo "[portman] Installing dependencies..."
apt-get update -qq
apt-get install -y python3 python3-pip iptables-persistent

pip3 install flask flask-httpauth werkzeug --break-system-packages

# ── 2. Install app ────────────────────────────────────────────────────────────
echo "[portman] Installing app..."
mkdir -p /opt/portman
cp app.py /opt/portman/app.py

# ── 3. systemd service ────────────────────────────────────────────────────────
echo "[portman] Installing systemd service..."
cp portman.service /etc/systemd/system/portman.service

systemctl daemon-reload
systemctl enable portman

echo ""
echo "========================================"
echo "  Edit the service file before starting:"
echo "  nano /etc/systemd/system/portman.service"
echo ""
echo "  PORTMAN_USER  — web UI username"
echo "  PORTMAN_PASS  — web UI password"
echo "  DEST_IP       — TrueNAS WireGuard peer IP (e.g. 10.0.0.2)"
echo "  WAN_IFACE     — run: ip route | grep default  (usually eth0)"
echo "  SECRET_KEY    — any random string"
echo ""
echo "  Then start it:"
echo "  systemctl daemon-reload"
echo "  systemctl start portman"
echo ""
echo "  Access at: http://$(curl -4s ifconfig.me 2>/dev/null || echo '<linode-ip>'):5000"
echo "========================================"
