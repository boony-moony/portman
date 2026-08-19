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

## Steam game servers behind CGNAT

Portman can route a dedicated home or Docker subnet out through the VPS. This
causes Steam's server directory and other external services to see the VPS
public IP instead of the home's CGNAT address.

1. Open **settings** and enable **Steam outbound via VPS**.
2. Enter the source subnet used only by the game server(s), such as
   `172.20.0.0/24`, and the existing WireGuard interface name.
3. Save settings. Portman enables narrow forwarding and masquerade rules on
   the VPS.
4. Download **home setup**, copy it to the home Docker/game host, inspect it,
   and run it as root after WireGuard is up.
5. Mark the relevant forwarding rules as **Steam game server**. This is a UI
   label; outbound selection is enforced by the source subnet.

The WireGuard peer configuration must also permit that routed subnet:

- On the home host, the VPS peer needs `AllowedIPs = 0.0.0.0/0` and
  `Table = off`. `Table = off` prevents the whole home host from using the VPS;
  the downloaded script adds a policy route only for the selected source.
- On the VPS, the home peer's `AllowedIPs` must include both the home tunnel
  address and the game source subnet (for example `10.10.0.2/32,
  172.20.0.0/24`).

Use a dedicated container VLAN/subnet where possible. Selecting the whole home
LAN will route every device in that subnet through the VPS. The current Steam
mode fixes outbound public-IP consistency; ordinary Portman DNAT still
masquerades inbound connections, so game servers do not receive original
player IPs.

The downloaded home rules need to run again after a reboot or WireGuard
restart. The simplest persistent setup is to call the saved script from the
WireGuard interface's `PostUp` hook or from a systemd oneshot unit ordered
after `wg-quick@<interface>` and Docker.

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
