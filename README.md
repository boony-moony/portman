# portman

A lightweight web UI for managing iptables DNAT port forwarding rules on a Linux VPS. Built for the common homelab setup where a VPS acts as a public gateway, forwarding traffic through a WireGuard tunnel to a home server.

## Use case

If you run game servers or other UDP/TCP services at home but don't have a static public IP, a common solution is:

```
Internet → VPS (public IP) → WireGuard tunnel → Home server (TrueNAS, etc.)
```

Managing iptables rules for this manually is tedious. Portman gives you a simple web UI to add and remove forwarding rules without touching the command line.

## What it does

For every rule you add, portman automatically creates:
- `iptables PREROUTING DNAT` — redirects incoming traffic to the tunnel
- `iptables FORWARD ACCEPT` — allows traffic through
- `iptables POSTROUTING MASQUERADE` — ensures replies route back correctly

Rules are persisted via `iptables-save` and survive reboots. Existing rules are loaded from iptables on startup so nothing gets duplicated.

## Requirements

- Debian/Ubuntu based VPS (tested on Linode)
- Python 3
- Root access (iptables requires it)
- WireGuard already configured between VPS and home server

## Installation

Copy the three files to your VPS and run the installer as root:

```bash
scp -r portman/ root@<your-vps-ip>:/root/portman
ssh root@<your-vps-ip>
cd /root/portman
chmod +x install.sh
./install.sh
```

The installer will:
- Install Python dependencies (`flask`, `flask-httpauth`, `werkzeug`)
- Install `iptables-persistent` for rule persistence
- Copy `app.py` to `/opt/portman/`
- Install and enable the systemd service

## Configuration

Edit the service file before starting:

```bash
nano /etc/systemd/system/portman.service
```

| Variable | Description |
|---|---|
| `PORTMAN_USER` | Web UI username |
| `PORTMAN_PASS` | Web UI password |
| `DEST_IP` | Default destination IP (your home server's WireGuard IP, e.g. `10.10.0.2`) |
| `WAN_IFACE` | Your VPS internet interface (find with `ip route \| grep default`) |
| `SECRET_KEY` | Any random string for Flask sessions |

Then start it:

```bash
systemctl daemon-reload
systemctl start portman
systemctl status portman
```

## Usage

Access the UI at `http://<your-vps-ip>:5000`. Log in with your configured credentials.

To forward a game server port (e.g. Minecraft on 25565):
1. Select protocol (TCP or UDP — add both if needed)
2. Enter the incoming port on the VPS (e.g. `25565`)
3. Enter the destination IP (your home server's WireGuard IP, e.g. `10.10.0.2`)
4. Enter the destination port (e.g. `25565`)
5. Click **ADD RULE**

To remove a rule, click **remove** next to it in the table.

## Security

Port 5000 should ideally not be publicly exposed. Restrict it via your VPS firewall (e.g. Linode Cloud Firewall) and access it over Tailscale or WireGuard only.

## Notes

- The `DEST_IP` env var pre-fills the destination IP field in the UI as a convenience
- Protocol numbers in iptables output (`6` = TCP, `17` = UDP) are handled automatically
- The service runs as root since iptables requires elevated privileges
# portman
