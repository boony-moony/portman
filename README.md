# portman

Lightweight web UI for managing iptables DNAT port forwarding on a Linux VPS. Built for the homelab setup where a VPS acts as a public entry point, forwarding traffic through WireGuard to a home server.

```
Internet → VPS (public IP) → WireGuard → Home server (TrueNAS, etc.)
```

## Requirements

- Debian/Ubuntu VPS with root access
- WireGuard already configured between VPS and home server
- Python 3

## Installation

```bash
scp -r portman/ root@<vps-ip>:/root/portman
ssh root@<vps-ip>
cd /root/portman
chmod +x install.sh
./install.sh
```

The installer prompts for fresh install, update, or remove, and optionally enables Cloudflare integration.

## Configuration

Edit the service file before starting:

```bash
nano /etc/systemd/system/portman.service
```

| Variable | Description |
|---|---|
| `PORTMAN_USER` | Web UI username |
| `PORTMAN_PASS` | Web UI password |
| `DEST_IP` | Default WireGuard peer IP (e.g. `10.10.0.2`) |
| `WAN_IFACE` | VPS internet interface (find with `ip route \| grep default`) |
| `SECRET_KEY` | Any random string for Flask sessions |

```bash
systemctl daemon-reload
systemctl start portman
```

## Usage

Access at `http://<vps-ip>:5000`. For HTTPS, run certbot after pointing a subdomain at the VPS:

```bash
certbot --nginx -d portman.yourdomain.com
```

Each rule you add creates three iptables entries automatically:
- `PREROUTING DNAT` — redirects incoming traffic into the tunnel
- `FORWARD ACCEPT` — allows traffic through
- `POSTROUTING MASQUERADE` — routes replies back correctly

Rules persist across reboots via `iptables-save`.

## Cloudflare integration

Enable during install or update. First visit to `/cloudflare` requires setting up a password and TOTP — keep the secret safe, losing it requires manually deleting `/opt/portman/cf_auth.json`.

From the Cloudflare page you can:
- Create A and SRV records for game servers (including Geyser/Bedrock)
- Optionally create the matching portman DNAT rule at the same time
- View and filter all DNS records in the zone
- Delete CF records, portman rules, or both per saved entry

## Security

- Port 5000 should not be publicly exposed — use HTTPS via nginx/certbot or restrict via firewall
- Cloudflare page is behind a separate password + TOTP session (1 hour expiry)
- API token and TOTP secret are stored in `/opt/portman/cf_auth.json` (chmod 600)
- Service runs as root (required for iptables)
