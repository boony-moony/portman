#!/bin/bash
# portman installer / updater — run as root on your Linode
set -e

IS_UPDATE=false
if [ -f /opt/portman/app.py ]; then
    IS_UPDATE=true
fi

if [ "$IS_UPDATE" = false ]; then
    echo "[portman] Installing dependencies..."
    apt-get update -qq
    apt-get install -y python3 python3-pip iptables-persistent nginx certbot python3-certbot-nginx
fi

echo "[portman] Updating Python packages..."
pip3 install flask flask-httpauth werkzeug --break-system-packages

if [ "$IS_UPDATE" = true ]; then
    echo "[portman] Existing installation detected — updating app..."
    systemctl stop portman 2>/dev/null || true
    cp app.py /opt/portman/app.py
    systemctl daemon-reload
    systemctl start portman
    echo ""
    echo "========================================"
    echo "  portman updated successfully!"
    echo "  Existing config preserved."
    echo "  Service restarted."
    echo "========================================"
else
    echo "[portman] Installing app..."
    mkdir -p /opt/portman
    cp app.py /opt/portman/app.py

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
fi
