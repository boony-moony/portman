#!/bin/bash
# portman installer / updater / remover — run as root on your Linode
set -e

# ── Root check ───────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "[portman] Please run as root."
    exit 1
fi

IS_INSTALLED=false
if [ -f /opt/portman/app.py ]; then
    IS_INSTALLED=true
fi

SETTINGS_FILE="/opt/portman/settings.json"

# ── Main menu ────────────────────────────────────────────────────────────────
echo ""
echo "  ██████╗  ██████╗ ██████╗ ████████╗███╗   ███╗  █████╗ ███╗  ██╗"
echo "  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝████╗ ████║ ██╔══██╗████╗ ██║"
echo "  ██████╔╝██║   ██║██████╔╝   ██║   ██╔████╔██║ ███████║██╔██╗██║"
echo "  ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██║╚██╔╝██║ ██╔══██║██║╚████║"
echo "  ██║     ╚██████╔╝██║  ██║   ██║   ██║ ╚═╝ ██║ ██║  ██║██║ ╚███║"
echo "  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝ ╚═╝  ╚═╝╚═╝  ╚══╝"
echo ""
echo "  iptables DNAT port forwarding manager"
echo ""

if [ "$IS_INSTALLED" = true ]; then
    echo "  Existing installation detected at /opt/portman"
    echo ""
    echo "  [1] Update   — pull latest app.py, preserve config"
    echo "  [2] Remove   — uninstall portman completely"
    echo "  [3] Cancel"
    echo ""
    read -p "  Choose [1/2/3]: " MENU_CHOICE
    case "$MENU_CHOICE" in
        1) ACTION="update" ;;
        2) ACTION="remove" ;;
        *) echo "  Cancelled."; exit 0 ;;
    esac
else
    echo "  No existing installation found."
    echo ""
    echo "  [1] Install  — fresh install"
    echo "  [2] Cancel"
    echo ""
    read -p "  Choose [1/2]: " MENU_CHOICE
    case "$MENU_CHOICE" in
        1) ACTION="install" ;;
        *) echo "  Cancelled."; exit 0 ;;
    esac
fi

# ── Remove ───────────────────────────────────────────────────────────────────
if [ "$ACTION" = "remove" ]; then
    echo ""
    read -p "[portman] This will remove portman completely. Are you sure? [y/N] " CONFIRM
    CONFIRM="${CONFIRM,,}"
    if [ "$CONFIRM" != "y" ]; then
        echo "  Cancelled."
        exit 0
    fi

    echo "[portman] Stopping and disabling service..."
    systemctl stop portman 2>/dev/null || true
    systemctl disable portman 2>/dev/null || true

    echo "[portman] Removing files..."
    rm -f /etc/systemd/system/portman.service
    rm -rf /opt/portman
    systemctl daemon-reload

    echo ""
    echo "========================================"
    echo "  portman removed."
    echo "  iptables rules were NOT touched."
    echo "  nginx configs prefixed portman-"
    echo "  in /etc/nginx/sites-* NOT removed."
    echo "========================================"
    exit 0
fi

# ── Install / Update shared steps ────────────────────────────────────────────
if [ "$ACTION" = "install" ]; then
    echo "[portman] Installing dependencies..."
    apt-get update -qq
    apt-get install -y python3 python3-pip iptables-persistent nginx certbot python3-certbot-nginx
fi

echo "[portman] Updating Python packages..."
pip3 install flask flask-httpauth werkzeug --break-system-packages

# ── Cloudflare integration ───────────────────────────────────────────────────
CF_CURRENTLY_ENABLED=false

if [ -f "$SETTINGS_FILE" ]; then
    if python3 -c "import json; d=json.load(open('$SETTINGS_FILE')); exit(0 if d.get('cloudflare_enabled') else 1)" 2>/dev/null; then
        CF_CURRENTLY_ENABLED=true
    fi
fi

if [ "$ACTION" = "update" ] && [ "$CF_CURRENTLY_ENABLED" = true ]; then
    echo ""
    echo "[portman] Cloudflare integration is currently enabled."
    read -p "  Reconfigure Cloudflare integration? [y/N] " CF_RECONFIG
    CF_RECONFIG="${CF_RECONFIG,,}"
    [ "$CF_RECONFIG" = "y" ] && ENABLE_CF=true || ENABLE_CF=false
    [ "$ENABLE_CF" = false ] && echo "[portman] Keeping existing Cloudflare config."
elif [ "$ACTION" = "update" ] && [ "$CF_CURRENTLY_ENABLED" = false ]; then
    echo ""
    read -p "[portman] Enable Cloudflare integration? [y/N] " ENABLE_CF_INPUT
    ENABLE_CF_INPUT="${ENABLE_CF_INPUT,,}"
    [ "$ENABLE_CF_INPUT" = "y" ] && ENABLE_CF=true || ENABLE_CF=false
else
    echo ""
    echo "[portman] Optional: Cloudflare integration lets you create DNS A + SRV"
    echo "          records from the portman web UI, protected by password + TOTP."
    read -p "  Enable Cloudflare integration? [y/N] " ENABLE_CF_INPUT
    ENABLE_CF_INPUT="${ENABLE_CF_INPUT,,}"
    [ "$ENABLE_CF_INPUT" = "y" ] && ENABLE_CF=true || ENABLE_CF=false
fi

mkdir -p /opt/portman

if [ "$ENABLE_CF" = true ]; then
    echo "[portman] Cloudflare integration enabled."
    if [ -f "$SETTINGS_FILE" ]; then
        python3 -c "
import json
with open('$SETTINGS_FILE') as f:
    d = json.load(f)
d['cloudflare_enabled'] = True
with open('$SETTINGS_FILE', 'w') as f:
    json.dump(d, f, indent=2)
"
    else
        python3 -c "
import json
with open('$SETTINGS_FILE', 'w') as f:
    json.dump({'certbot_email': '', 'cloudflare_enabled': True}, f, indent=2)
"
    fi
    echo "[portman] Configure API token + Zone ID at /cloudflare after starting."
    echo "          You will be prompted to set a password + TOTP on first visit."
else
    if [ -f "$SETTINGS_FILE" ]; then
        python3 -c "
import json
with open('$SETTINGS_FILE') as f:
    d = json.load(f)
d['cloudflare_enabled'] = False
with open('$SETTINGS_FILE', 'w') as f:
    json.dump(d, f, indent=2)
" 2>/dev/null || true
    fi
fi

# ── Deploy app ───────────────────────────────────────────────────────────────
if [ "$ACTION" = "update" ]; then
    echo "[portman] Stopping service..."
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
