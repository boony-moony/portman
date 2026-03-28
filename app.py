#!/usr/bin/env python3
"""
portman - iptables DNAT port forwarding manager
Reads existing rules, lets you add/edit/remove via web UI
Supports optional label and domain/subdomain per rule
Automatically manages nginx reverse proxy configs; optional SSL via certbot
Optional Cloudflare DNS integration (A + SRV records) protected by TOTP
"""

import subprocess
import re
import json
import os
import time
import hmac
import hashlib
import base64
import urllib.request
import urllib.error
import uuid
from flask import Flask, request, jsonify, session, redirect, url_for, make_response
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-production")
auth = HTTPBasicAuth()

# --- Config ---
USERNAME      = os.environ.get("PORTMAN_USER", "admin")
PASSWORD_HASH = generate_password_hash(os.environ.get("PORTMAN_PASS", "admin"))
DEFAULT_DEST_IP = os.environ.get("DEST_IP", "")
WAN_IFACE     = os.environ.get("WAN_IFACE", "eth0")
DEMO_MODE     = os.environ.get("DEMO_MODE", "").lower() in ("1", "true", "yes")

def demo_block():
    """Return a 403 response if running in demo mode."""
    if DEMO_MODE:
        return jsonify({"ok": False, "error": "demo mode — read only"}), 403
    return None

LABELS_FILE   = "/opt/portman/labels.json"
SETTINGS_FILE = "/opt/portman/settings.json"
CF_AUTH_FILE  = "/opt/portman/cf_auth.json"
NGINX_AVAIL   = "/etc/nginx/sites-available"
NGINX_ENABLED = "/etc/nginx/sites-enabled"

@auth.verify_password
def verify_password(username, password):
    if username == USERNAME and check_password_hash(PASSWORD_HASH, password):
        return username

def run(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()

PROTO_MAP = {"6": "tcp", "17": "udp", "tcp": "tcp", "udp": "udp"}

# ── Labels & Settings ────────────────────────────────────────────────────────

def label_key(proto, src_port):
    return f"{proto}:{src_port}"

def load_labels():
    try:
        with open(LABELS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_labels(labels):
    try:
        os.makedirs(os.path.dirname(LABELS_FILE), exist_ok=True)
        with open(LABELS_FILE, "w") as f:
            json.dump(labels, f, indent=2)
    except Exception as e:
        print(f"Error saving labels: {e}")

def load_settings():
    try:
        with open(SETTINGS_FILE) as f:
            return json.load(f)
    except Exception:
        return {"certbot_email": "", "cloudflare_enabled": False}

def save_settings(settings):
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        print(f"Error saving settings: {e}")

# ── Cloudflare auth (TOTP + password, stored separately) ────────────────────

def load_cf_auth():
    try:
        with open(CF_AUTH_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_cf_auth(data):
    os.makedirs(os.path.dirname(CF_AUTH_FILE), exist_ok=True)
    with open(CF_AUTH_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(CF_AUTH_FILE, 0o600)

def cf_is_setup():
    d = load_cf_auth()
    return bool(d.get("password_hash")) and bool(d.get("totp_secret"))

def cf_session_valid():
    return session.get("cf_authed") and time.time() - session.get("cf_authed_at", 0) < 3600

# ── TOTP (RFC 6238) — no external lib required ──────────────────────────────

def _totp_generate_secret():
    return base64.b32encode(os.urandom(20)).decode("utf-8")

def _totp_code(secret, t=None):
    if t is None:
        t = int(time.time()) // 30
    key = base64.b32decode(secret.upper())
    msg = t.to_bytes(8, "big")
    h   = hmac.new(key, msg, hashlib.sha1).digest()
    o   = h[-1] & 0x0F
    code = (int.from_bytes(h[o:o+4], "big") & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"

def totp_verify(secret, code):
    code = str(code).strip()
    for delta in (-1, 0, 1):
        if hmac.compare_digest(_totp_code(secret, int(time.time()) // 30 + delta), code):
            return True
    return False

def totp_provisioning_uri(secret, account="portman-cloudflare", issuer="portman"):
    return f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}"

# ── Cloudflare API helpers ───────────────────────────────────────────────────

def cf_api(method, path, payload=None):
    d = load_cf_auth()
    token   = d.get("api_token", "")
    zone_id = d.get("zone_id", "")
    if not token or not zone_id:
        raise RuntimeError("Cloudflare API token or Zone ID not configured")
    url  = f"https://api.cloudflare.com/client/v4/zones/{zone_id}{path}"
    data = json.dumps(payload).encode() if payload else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"CF API {e.code}: {body}")

def cf_list_records(name=None, rtype=None):
    params = []
    if name:  params.append(f"name={urllib.parse.quote(name)}")
    if rtype: params.append(f"type={rtype}")
    qs = ("?" + "&".join(params)) if params else ""
    return cf_api("GET", f"/dns_records{qs}")

def cf_create_a_record(name, ip):
    """Create A record if it doesn't already exist."""
    import urllib.parse
    existing = cf_list_records(name=name, rtype="A")
    for r in existing.get("result", []):
        if r["name"] == name:
            return {"ok": True, "msg": "A record already exists"}
    result = cf_api("POST", "/dns_records", {
        "type": "A", "name": name, "content": ip, "ttl": 1, "proxied": False
    })
    if not result.get("success"):
        raise RuntimeError(str(result.get("errors")))
    return {"ok": True, "msg": "A record created"}

def cf_create_srv_record(subdomain, target, port, proto="tcp"):
    """Create SRV record for Minecraft. subdomain = e.g. 'fly' for fly.linuslinus.com"""
    import urllib.parse
    d = load_cf_auth()
    zone_name = d.get("zone_name", "")
    srv_name  = f"_minecraft._{proto}.{subdomain}"
    existing  = cf_list_records(name=f"{srv_name}.{zone_name}", rtype="SRV")
    for r in existing.get("result", []):
        if r["name"].startswith(f"_minecraft._{proto}.{subdomain}"):
            return {"ok": True, "msg": "SRV record already exists"}
    result = cf_api("POST", "/dns_records", {
        "type": "SRV",
        "name": srv_name,
        "data": {
            "service":  "_minecraft",
            "proto":    f"_{proto}",
            "name":     subdomain,
            "priority": 0,
            "weight":   5,
            "port":     int(port),
            "target":   target
        },
        "ttl": 1
    })
    if not result.get("success"):
        raise RuntimeError(str(result.get("errors")))
    return {"ok": True, "msg": "SRV record created"}

# ── nginx helpers ────────────────────────────────────────────────────────────

def _valid_domain(domain):
    return bool(domain) and bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$', domain)) and '..' not in domain

def _nginx_present():
    return os.path.isdir(NGINX_AVAIL) and os.path.isdir(NGINX_ENABLED)

def write_nginx_config(domain, dest_ip, dest_port):
    if not domain or not _valid_domain(domain) or not _nginx_present():
        return
    conf = (
        "server {\n"
        "    listen 80;\n"
        f"    server_name {domain};\n"
        "\n"
        "    location / {\n"
        f"        proxy_pass http://{dest_ip}:{dest_port};\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "        proxy_set_header X-Forwarded-Proto $scheme;\n"
        "    }\n"
        "}\n"
    )
    conf_path    = os.path.join(NGINX_AVAIL,   f"portman-{domain}")
    enabled_path = os.path.join(NGINX_ENABLED, f"portman-{domain}")
    try:
        with open(conf_path, "w") as fh:
            fh.write(conf)
        if not os.path.exists(enabled_path):
            os.symlink(conf_path, enabled_path)
        run("nginx -s reload", check=False)
    except Exception as e:
        print(f"nginx config error: {e}")

def remove_nginx_config(domain):
    if not domain or not _valid_domain(domain) or not _nginx_present():
        return
    for path in [
        os.path.join(NGINX_ENABLED, f"portman-{domain}"),
        os.path.join(NGINX_AVAIL,   f"portman-{domain}"),
    ]:
        try:
            os.remove(path)
        except Exception:
            pass
    run("nginx -s reload", check=False)

def ssl_active(domain):
    if not domain or not _valid_domain(domain):
        return False
    return os.path.exists(f"/etc/letsencrypt/live/{domain}/fullchain.pem")

# ── iptables helpers ─────────────────────────────────────────────────────────

def get_existing_rules():
    rules  = []
    labels = load_labels()
    try:
        output = run("iptables -t nat -L PREROUTING -n --line-numbers")
        for line in output.splitlines():
            m = re.match(
                r'(\d+)\s+DNAT\s+(\w+)\s+--\s+\S+\s+\S+\s+\S+\s+dpt:(\d+)\s+to:([^:]+):(\d+)',
                line.strip()
            )
            if m:
                proto_raw = m.group(2)
                proto = PROTO_MAP.get(proto_raw, proto_raw)
                if proto not in ("tcp", "udp"):
                    continue
                src_port = int(m.group(3))
                key  = label_key(proto, src_port)
                meta = labels.get(key, {})
                dom  = meta.get("domain", "")
                rules.append({
                    "line":       int(m.group(1)),
                    "proto":      proto,
                    "src_port":   src_port,
                    "dest_ip":    m.group(4),
                    "dest_port":  int(m.group(5)),
                    "label":      meta.get("label", ""),
                    "domain":     dom,
                    "ssl_active": ssl_active(dom),
                })
    except Exception as e:
        print(f"Error reading iptables: {e}")
    return rules

def add_rule(proto, src_port, dest_ip, dest_port):
    run(f"iptables -t nat -A PREROUTING -i {WAN_IFACE} -p {proto} --dport {src_port} -j DNAT --to-destination {dest_ip}:{dest_port}")
    run(f"iptables -A FORWARD -p {proto} -d {dest_ip} --dport {dest_port} -j ACCEPT")
    run(f"iptables -t nat -A POSTROUTING -p {proto} -d {dest_ip} --dport {dest_port} -j MASQUERADE")
    persist()

def remove_rule(proto, src_port, dest_ip, dest_port):
    run(f"iptables -t nat -D PREROUTING -i {WAN_IFACE} -p {proto} --dport {src_port} -j DNAT --to-destination {dest_ip}:{dest_port}", check=False)
    run(f"iptables -D FORWARD -p {proto} -d {dest_ip} --dport {dest_port} -j ACCEPT", check=False)
    run(f"iptables -t nat -D POSTROUTING -p {proto} -d {dest_ip} --dport {dest_port} -j MASQUERADE", check=False)
    persist()

def persist():
    try:
        run("iptables-save > /etc/iptables/rules.v4")
    except Exception:
        try:
            run("iptables-save > /etc/iptables.rules")
        except Exception:
            pass

# ── Routes — main app ────────────────────────────────────────────────────────

@app.route("/")
@auth.login_required
def index():
    settings = load_settings()
    cf_enabled = settings.get("cloudflare_enabled", False)
    return HTML_PAGE         .replace("__CF_ENABLED__", "true" if cf_enabled else "false")         .replace("__DEMO_MODE__", "true" if DEMO_MODE else "false")

@app.route("/api/rules", methods=["GET"])
@auth.login_required
def api_rules():
    return jsonify(get_existing_rules())

@app.route("/api/rules", methods=["POST"])
@auth.login_required
def api_add():
    blocked = demo_block()
    if blocked: return blocked
    data = request.json
    try:
        proto     = data["proto"].lower()
        src_port  = int(data["src_port"])
        dest_ip   = data["dest_ip"].strip()
        dest_port = int(data["dest_port"])
        label     = data.get("label", "").strip()
        domain    = data.get("domain", "").strip()
        assert proto in ("tcp", "udp")
        assert 1 <= src_port <= 65535
        assert 1 <= dest_port <= 65535
        add_rule(proto, src_port, dest_ip, dest_port)
        labels = load_labels()
        labels[label_key(proto, src_port)] = {"label": label, "domain": domain}
        save_labels(labels)
        if domain:
            write_nginx_config(domain, dest_ip, dest_port)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/rules", methods=["PUT"])
@auth.login_required
def api_edit():
    blocked = demo_block()
    if blocked: return blocked
    data = request.json
    try:
        old_proto     = data["old_proto"].lower()
        old_src_port  = int(data["old_src_port"])
        old_dest_ip   = data["old_dest_ip"].strip()
        old_dest_port = int(data["old_dest_port"])
        new_proto     = data["new_proto"].lower()
        new_src_port  = int(data["new_src_port"])
        new_dest_ip   = data["new_dest_ip"].strip()
        new_dest_port = int(data["new_dest_port"])
        label         = data.get("label", "").strip()
        new_domain    = data.get("domain", "").strip()
        assert new_proto in ("tcp", "udp")
        assert 1 <= new_src_port <= 65535
        assert 1 <= new_dest_port <= 65535

        labels     = load_labels()
        old_key    = label_key(old_proto, old_src_port)
        old_domain = labels.get(old_key, {}).get("domain", "")

        remove_rule(old_proto, old_src_port, old_dest_ip, old_dest_port)
        add_rule(new_proto, new_src_port, new_dest_ip, new_dest_port)

        if old_key in labels:
            del labels[old_key]
        labels[label_key(new_proto, new_src_port)] = {"label": label, "domain": new_domain}
        save_labels(labels)

        if old_domain and old_domain != new_domain:
            remove_nginx_config(old_domain)
        if new_domain:
            write_nginx_config(new_domain, new_dest_ip, new_dest_port)
        elif old_domain and not new_domain:
            remove_nginx_config(old_domain)

        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/rules", methods=["DELETE"])
@auth.login_required
def api_remove():
    blocked = demo_block()
    if blocked: return blocked
    data = request.json
    try:
        proto     = data["proto"].lower()
        src_port  = int(data["src_port"])
        dest_ip   = data["dest_ip"].strip()
        dest_port = int(data["dest_port"])
        labels    = load_labels()
        key       = label_key(proto, src_port)
        domain    = labels.get(key, {}).get("domain", "")
        remove_rule(proto, src_port, dest_ip, dest_port)
        if key in labels:
            del labels[key]
        save_labels(labels)
        if domain:
            remove_nginx_config(domain)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/settings", methods=["GET"])
@auth.login_required
def api_get_settings():
    return jsonify(load_settings())

@app.route("/api/settings", methods=["POST"])
@auth.login_required
def api_save_settings():
    blocked = demo_block()
    if blocked: return blocked
    data     = request.json
    settings = load_settings()
    if "certbot_email" in data:
        settings["certbot_email"] = data["certbot_email"].strip()
    save_settings(settings)
    return jsonify({"ok": True})

@app.route("/api/ssl", methods=["POST"])
@auth.login_required
def api_ssl():
    blocked = demo_block()
    if blocked: return blocked
    data   = request.json
    domain = data.get("domain", "").strip()
    if not domain or not _valid_domain(domain):
        return jsonify({"ok": False, "error": "invalid domain"}), 400
    settings = load_settings()
    email    = settings.get("certbot_email", "").strip()
    if not email:
        return jsonify({"ok": False, "error": "set certbot email in settings first"}), 400
    try:
        result = subprocess.run(
            ["certbot", "--nginx", "-d", domain,
             "--non-interactive", "--agree-tos", "-m", email],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        return jsonify({"ok": True})
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "certbot timed out"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ── Routes — Cloudflare ──────────────────────────────────────────────────────

@app.route("/cloudflare")
@auth.login_required
def cf_page():
    settings = load_settings()
    if not settings.get("cloudflare_enabled", False):
        return "Cloudflare integration is not enabled.", 403
    if not cf_is_setup():
        return CF_SETUP_PAGE
    if not cf_session_valid():
        return CF_LOGIN_PAGE
    d = load_cf_auth()
    token_set   = bool(d.get("api_token"))
    zone_id_set = bool(d.get("zone_id"))
    zone_name   = d.get("zone_name", "")
    return CF_MAIN_PAGE \
        .replace("__TOKEN_SET__",   "true" if token_set else "false") \
        .replace("__ZONE_ID_SET__", "true" if zone_id_set else "false") \
        .replace("__DEMO_MODE__",   "true" if DEMO_MODE else "false")

@app.route("/api/cf/setup", methods=["POST"])
@auth.login_required
def cf_setup():
    blocked = demo_block()
    if blocked: return blocked
    settings = load_settings()
    if not settings.get("cloudflare_enabled", False):
        return jsonify({"ok": False, "error": "not enabled"}), 403
    if cf_is_setup():
        return jsonify({"ok": False, "error": "already set up"}), 400
    data     = request.json
    password = data.get("password", "").strip()
    secret   = data.get("totp_secret", "").strip()
    code     = data.get("totp_code", "").strip()
    if len(password) < 8:
        return jsonify({"ok": False, "error": "password must be at least 8 characters"})
    if not secret or not totp_verify(secret, code):
        return jsonify({"ok": False, "error": "invalid TOTP code — scan the QR code and enter the 6-digit code"})
    save_cf_auth({"password_hash": generate_password_hash(password), "totp_secret": secret})
    session["cf_authed"]    = True
    session["cf_authed_at"] = time.time()
    return jsonify({"ok": True})

@app.route("/api/cf/generate-totp", methods=["POST"])
@auth.login_required
def cf_generate_totp():
    settings = load_settings()
    if not settings.get("cloudflare_enabled", False):
        return jsonify({"ok": False, "error": "not enabled"}), 403
    secret = _totp_generate_secret()
    uri    = totp_provisioning_uri(secret)
    return jsonify({"ok": True, "secret": secret, "uri": uri})

@app.route("/api/cf/login", methods=["POST"])
@auth.login_required
def cf_login():
    settings = load_settings()
    if not settings.get("cloudflare_enabled", False):
        return jsonify({"ok": False, "error": "not enabled"}), 403
    data     = request.json
    password = data.get("password", "").strip()
    code     = data.get("totp_code", "").strip()
    d        = load_cf_auth()
    if not check_password_hash(d.get("password_hash", ""), password):
        return jsonify({"ok": False, "error": "invalid password"})
    if not totp_verify(d.get("totp_secret", ""), code):
        return jsonify({"ok": False, "error": "invalid TOTP code"})
    session["cf_authed"]    = True
    session["cf_authed_at"] = time.time()
    return jsonify({"ok": True})

@app.route("/api/cf/logout", methods=["POST"])
@auth.login_required
def cf_logout():
    session.pop("cf_authed", None)
    session.pop("cf_authed_at", None)
    return jsonify({"ok": True})

@app.route("/api/cf/config", methods=["GET"])
@auth.login_required
def cf_get_config():
    if not cf_session_valid():
        return jsonify({"ok": False, "error": "not authenticated"}), 401
    d = load_cf_auth()
    return jsonify({
        "ok":          True,
        "token_set":   bool(d.get("api_token")),
        "zone_id_set": bool(d.get("zone_id")),
        "zone_name":   d.get("zone_name", ""),
    })

@app.route("/api/cf/config", methods=["POST"])
@auth.login_required
def cf_save_config():
    blocked = demo_block()
    if blocked: return blocked
    if not cf_session_valid():
        return jsonify({"ok": False, "error": "not authenticated"}), 401
    data      = request.json
    d         = load_cf_auth()
    api_token = data.get("api_token", "").strip()
    zone_id   = data.get("zone_id", "").strip()
    zone_name = data.get("zone_name", "").strip()
    if api_token:
        d["api_token"] = api_token
    if zone_id:
        d["zone_id"] = zone_id
    if zone_name:
        d["zone_name"] = zone_name
    save_cf_auth(d)
    return jsonify({"ok": True})

@app.route("/api/cf/dns", methods=["POST"])
@auth.login_required
def cf_create_dns():
    """Create A record + TCP SRV (and optionally UDP SRV) for a rule."""
    blocked = demo_block()
    if blocked: return blocked
    if not cf_session_valid():
        return jsonify({"ok": False, "error": "not authenticated"}), 401
    data        = request.json
    label       = data.get("label", "").strip()
    subdomain   = data.get("subdomain", "").strip()
    full_domain = data.get("full_domain", "").strip()
    linode_ip   = data.get("linode_ip", "").strip()
    srv_target  = data.get("srv_target", "").strip()
    port        = int(data.get("port", 0))
    add_udp     = data.get("add_udp", False)
    geyser_port = data.get("geyser_port", 0)
    dest_ip     = data.get("dest_ip", "").strip()
    dest_port   = int(data.get("dest_port", 0) or 0)
    create_rule = data.get("create_portman_rule", False)

    if not all([subdomain, full_domain, linode_ip, srv_target, port]):
        return jsonify({"ok": False, "error": "missing required fields"})

    results = []
    try:
        r = cf_create_a_record(full_domain, linode_ip)
        results.append(f"A record ({full_domain}): {r['msg']}")

        # Also create A record for SRV target if it doesn't already exist
        if srv_target and srv_target != full_domain:
            r = cf_create_a_record(srv_target, linode_ip)
            results.append(f"A record ({srv_target}): {r['msg']}")

        r = cf_create_srv_record(subdomain, srv_target, port, "tcp")
        results.append(f"SRV TCP: {r['msg']}")

        if add_udp:
            r = cf_create_srv_record(subdomain, srv_target, port, "udp")
            results.append(f"SRV UDP: {r['msg']}")

        if geyser_port:
            r = cf_create_srv_record(subdomain, srv_target, geyser_port, "udp")
            results.append(f"Geyser SRV UDP ({geyser_port}): {r['msg']}")

        # Optionally create portman DNAT rules
        if create_rule and dest_ip and dest_port:
            _dest_port = dest_port
            add_rule("tcp", port, dest_ip, _dest_port)
            lbl = load_labels()
            lbl[label_key("tcp", port)] = {"label": label or subdomain, "domain": full_domain}
            save_labels(lbl)
            results.append(f"Portman TCP rule: :{port} → {dest_ip}:{_dest_port}")
            if add_udp:
                add_rule("udp", port, dest_ip, _dest_port)
                lbl = load_labels()
                lbl[label_key("udp", port)] = {"label": label or subdomain, "domain": full_domain}
                save_labels(lbl)
                results.append(f"Portman UDP rule: :{port} → {dest_ip}:{_dest_port}")
            if geyser_port:
                add_rule("udp", geyser_port, dest_ip, geyser_port)
                lbl = load_labels()
                lbl[label_key("udp", geyser_port)] = {"label": f"{label or subdomain} (geyser)", "domain": ""}
                save_labels(lbl)
                results.append(f"Portman Geyser UDP rule: :{geyser_port} → {dest_ip}:{geyser_port}")

        # Save entry to cf_auth so it shows in the records list
        d = load_cf_auth()
        entries = d.get("dns_entries", [])

        # Collect CF record IDs created in this run for easy bulk delete later
        cf_record_ids = []
        # Re-fetch zone records to find the IDs we just created
        try:
            zone_result = cf_api("GET", "/dns_records?per_page=100")
            for rec in zone_result.get("result", []):
                rname = rec.get("name", "")
                if rname == full_domain and rec.get("type") == "A":
                    cf_record_ids.append(rec["id"])
                elif f"_{subdomain}" in rname or (f".{subdomain}." in rname) or rname.endswith(f".{subdomain}"):
                    if rec.get("type") == "SRV":
                        cf_record_ids.append(rec["id"])
        except Exception:
            pass

        # Collect portman rule keys created
        portman_keys = []
        if create_rule and dest_ip and dest_port:
            portman_keys.append(label_key("tcp", port))
            if add_udp:
                portman_keys.append(label_key("udp", port))
            if geyser_port:
                portman_keys.append(label_key("udp", geyser_port))

        entry_id = str(uuid.uuid4())[:8]
        entries.append({
            "id":            entry_id,
            "label":         label or subdomain,
            "subdomain":     subdomain,
            "full_domain":   full_domain,
            "port":          port,
            "geyser_port":   geyser_port or None,
            "add_udp":       add_udp,
            "dest_ip":       dest_ip if create_rule else "",
            "dest_port":     dest_port if create_rule else None,
            "cf_record_ids": cf_record_ids,
            "portman_keys":  portman_keys,
        })
        d["dns_entries"] = entries
        save_cf_auth(d)

        return jsonify({"ok": True, "results": results, "entry_id": entry_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "partial": results})

@app.route("/api/cf/dns", methods=["GET"])
@auth.login_required
def cf_list_dns():
    if not cf_session_valid():
        return jsonify({"ok": False, "error": "not authenticated"}), 401
    d = load_cf_auth()
    return jsonify({"ok": True, "entries": d.get("dns_entries", [])})

@app.route("/api/cf/dns/<int:index>", methods=["DELETE"])
@auth.login_required
def cf_delete_dns(index):
    blocked = demo_block()
    if blocked: return blocked
    if not cf_session_valid():
        return jsonify({"ok": False, "error": "not authenticated"}), 401
    data       = request.json or {}
    delete_cf  = data.get("delete_cf", False)
    delete_rules = data.get("delete_rules", False)
    d = load_cf_auth()
    entries = d.get("dns_entries", [])
    if not (0 <= index < len(entries)):
        return jsonify({"ok": False, "error": "entry not found"}), 404

    entry   = entries[index]
    results = []
    errors  = []

    # Delete CF DNS records
    if delete_cf:
        for rec_id in entry.get("cf_record_ids", []):
            try:
                cf_api("DELETE", f"/dns_records/{rec_id}")
                results.append(f"CF record {rec_id[:8]}... deleted")
            except Exception as e:
                errors.append(f"CF record {rec_id[:8]}...: {e}")

    # Delete portman iptables rules
    if delete_rules:
        labels = load_labels()
        for key in entry.get("portman_keys", []):
            meta = labels.get(key, {})
            try:
                proto, src_port = key.split(":")
                src_port = int(src_port)
                dest_ip   = entry.get("dest_ip", "")
                dest_port = entry.get("dest_port") or src_port
                if dest_ip:
                    remove_rule(proto, src_port, dest_ip, dest_port)
                    results.append(f"Portman rule {key} removed")
                if key in labels:
                    del labels[key]
            except Exception as e:
                errors.append(f"Portman rule {key}: {e}")
        save_labels(labels)

    entries.pop(index)
    d["dns_entries"] = entries
    save_cf_auth(d)
    return jsonify({"ok": True, "results": results, "errors": errors})


@app.route("/api/cf/zone_records", methods=["GET"])
@auth.login_required
def cf_zone_records():
    if not cf_session_valid():
        return jsonify({"ok": False, "error": "not authenticated"}), 401
    try:
        result = cf_api("GET", "/dns_records?per_page=100")
        if not result.get("success"):
            raise RuntimeError(str(result.get("errors")))
        records = result.get("result", [])
        # Load portman-created labels for cross-referencing
        d = load_cf_auth()
        entries = d.get("dns_entries", [])
        portman_domains = {e["full_domain"]: e["label"] for e in entries}
        portman_subdomains = {e["subdomain"]: e["label"] for e in entries}

        out = []
        for r in records:
            rtype = r.get("type", "")
            name  = r.get("name", "")
            # Classify
            if rtype == "SRV" and "_minecraft" in name:
                category = "minecraft"
            elif rtype == "SRV":
                category = "srv"
            elif rtype == "A":
                category = "a"
            else:
                category = "other"

            # Try to match a portman label
            label = portman_domains.get(name, "")
            if not label:
                for sub, lbl in portman_subdomains.items():
                    if name.endswith("." + sub + ".") or ("." + sub + ".") in name or name.endswith(sub):
                        label = lbl
                        break

            content = r.get("content", "")
            if rtype == "SRV":
                data = r.get("data", {})
                content = f'{data.get("target","")}:{data.get("port","")}'

            out.append({
                "id":       r.get("id"),
                "type":     rtype,
                "name":     name,
                "content":  content,
                "category": category,
                "label":    label,
                "proxied":  r.get("proxied", False),
            })
        return jsonify({"ok": True, "records": out})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ── Cloudflare pages (embedded HTML) ─────────────────────────────────────────

CF_SETUP_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>portman — cloudflare setup</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#0d0d0f; --surface:#15151a; --border:#2a2a35; --accent:#00e5ff; --accent2:#ff4d6d; --text:#e8e8f0; --muted:#6b6b80; --mono:'JetBrains Mono',monospace; --display:'Syne',sans-serif; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:var(--mono); min-height:100vh; display:flex; align-items:center; justify-content:center; padding:2rem; }
  .card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:2.5rem; width:100%; max-width:440px; }
  h1 { font-family:var(--display); color:var(--accent); font-size:1.6rem; margin-bottom:0.25rem; }
  .sub { color:var(--muted); font-size:0.75rem; margin-bottom:2rem; }
  label { display:block; font-size:0.65rem; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-top:1.25rem; margin-bottom:0.4rem; }
  input { width:100%; background:var(--bg); border:1px solid var(--border); color:var(--text); font-family:var(--mono); font-size:0.85rem; padding:0.6rem 0.8rem; border-radius:4px; outline:none; transition:border-color 0.15s; }
  input:focus { border-color:var(--accent); }
  .btn { margin-top:1.5rem; width:100%; background:var(--accent); color:#000; border:none; border-radius:4px; padding:0.75rem; font-family:var(--mono); font-size:0.85rem; font-weight:700; cursor:pointer; letter-spacing:1px; transition:opacity 0.15s; }
  .btn:hover { opacity:0.85; } .btn:disabled { opacity:0.4; cursor:default; }
  .qr-wrap { margin-top:1.25rem; text-align:center; }
  .qr-wrap img { border:4px solid white; border-radius:4px; max-width:200px; }
  .qr-wrap .secret { font-size:0.7rem; color:var(--muted); margin-top:0.5rem; word-break:break-all; }
  .btn-gen { background:none; border:1px solid var(--border); color:var(--accent); border-radius:4px; padding:0.5rem 1rem; font-family:var(--mono); font-size:0.75rem; cursor:pointer; margin-top:1rem; width:100%; transition:all 0.15s; }
  .btn-gen:hover { border-color:var(--accent); }
  .err { color:var(--accent2); font-size:0.75rem; margin-top:0.75rem; display:none; }
  .ok  { color:#3ddc84; font-size:0.75rem; margin-top:0.75rem; display:none; }
  .warn { background:rgba(255,179,71,0.08); border:1px solid rgba(255,179,71,0.3); color:#ffb347; border-radius:4px; padding:0.75rem 1rem; font-size:0.72rem; margin-bottom:1.5rem; line-height:1.5; }
</style>
</head>
<body>
<div class="card">
  <h1>cloudflare setup</h1>
  <p class="sub">first-time setup — this runs once</p>
  <div class="warn">&#9888; Set a strong password and save the TOTP secret somewhere safe. If you lose access you will need to manually delete <code>/opt/portman/cf_auth.json</code> and redo setup.</div>

  <label>Password <span style="font-size:0.6rem;opacity:0.6">(min 8 chars)</span></label>
  <input type="password" id="password" placeholder="choose a strong password">

  <label>Confirm password</label>
  <input type="password" id="password2" placeholder="confirm password">

  <label>Authenticator app</label>
  <button class="btn-gen" onclick="generateTOTP()">Generate QR code</button>
  <div class="qr-wrap" id="qr-wrap" style="display:none">
    <img id="qr-img" src="" alt="QR code">
    <div class="secret" id="totp-secret-display"></div>
  </div>
  <input type="hidden" id="totp-secret" value="">

  <label>TOTP code <span style="font-size:0.6rem;opacity:0.6">(from your authenticator)</span></label>
  <input type="text" id="totp-code" placeholder="000000" maxlength="6" autocomplete="one-time-code">

  <div class="err" id="err"></div>
  <button class="btn" id="btn" onclick="doSetup()">COMPLETE SETUP</button>
</div>
<script>
async function generateTOTP() {
  var res  = await fetch('/api/cf/generate-totp', {method:'POST'});
  var data = await res.json();
  if (!data.ok) { showErr(data.error); return; }
  document.getElementById('totp-secret').value = data.secret;
  document.getElementById('totp-secret-display').textContent = 'Manual key: ' + data.secret;
  // Use a QR code API to render the otpauth URI
  var qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(data.uri);
  document.getElementById('qr-img').src = qrUrl;
  document.getElementById('qr-wrap').style.display = 'block';
}
async function doSetup() {
  var pw  = document.getElementById('password').value;
  var pw2 = document.getElementById('password2').value;
  var sec = document.getElementById('totp-secret').value;
  var cod = document.getElementById('totp-code').value.trim();
  if (pw !== pw2) { showErr('passwords do not match'); return; }
  if (!sec) { showErr('generate a QR code first'); return; }
  if (!cod) { showErr('enter the 6-digit code from your authenticator'); return; }
  var btn = document.getElementById('btn');
  btn.disabled = true; btn.textContent = 'SETTING UP...';
  var res  = await fetch('/api/cf/setup', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({password:pw, totp_secret:sec, totp_code:cod})});
  var data = await res.json();
  btn.disabled = false; btn.textContent = 'COMPLETE SETUP';
  if (data.ok) { window.location.href = '/cloudflare'; }
  else showErr(data.error);
}
function showErr(msg) { var e = document.getElementById('err'); e.textContent = msg; e.style.display = 'block'; }
</script>
</body>
</html>"""

CF_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>portman — cloudflare login</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#0d0d0f; --surface:#15151a; --border:#2a2a35; --accent:#00e5ff; --accent2:#ff4d6d; --text:#e8e8f0; --muted:#6b6b80; --mono:'JetBrains Mono',monospace; --display:'Syne',sans-serif; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:var(--mono); min-height:100vh; display:flex; align-items:center; justify-content:center; padding:2rem; }
  .card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:2.5rem; width:100%; max-width:380px; }
  h1 { font-family:var(--display); color:var(--accent); font-size:1.6rem; margin-bottom:0.25rem; }
  .sub { color:var(--muted); font-size:0.75rem; margin-bottom:2rem; }
  label { display:block; font-size:0.65rem; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-top:1.25rem; margin-bottom:0.4rem; }
  input { width:100%; background:var(--bg); border:1px solid var(--border); color:var(--text); font-family:var(--mono); font-size:0.85rem; padding:0.6rem 0.8rem; border-radius:4px; outline:none; transition:border-color 0.15s; }
  input:focus { border-color:var(--accent); }
  .btn { margin-top:1.5rem; width:100%; background:var(--accent); color:#000; border:none; border-radius:4px; padding:0.75rem; font-family:var(--mono); font-size:0.85rem; font-weight:700; cursor:pointer; letter-spacing:1px; transition:opacity 0.15s; }
  .btn:hover { opacity:0.85; } .btn:disabled { opacity:0.4; cursor:default; }
  .err { color:var(--accent2); font-size:0.75rem; margin-top:0.75rem; display:none; }
  .back { display:block; text-align:center; margin-top:1rem; font-size:0.72rem; color:var(--muted); text-decoration:none; }
  .back:hover { color:var(--text); }
</style>
</head>
<body>
<div class="card">
  <h1>cloudflare</h1>
  <p class="sub">authentication required</p>
  <label>Password</label>
  <input type="password" id="password" placeholder="cloudflare page password">
  <label>TOTP code</label>
  <input type="text" id="totp-code" placeholder="000000" maxlength="6" autocomplete="one-time-code">
  <div class="err" id="err"></div>
  <button class="btn" id="btn" onclick="doLogin()">UNLOCK</button>
  <a href="/" class="back">← back to portman</a>
</div>
<script>
async function doLogin() {
  var pw  = document.getElementById('password').value;
  var cod = document.getElementById('totp-code').value.trim();
  var btn = document.getElementById('btn');
  btn.disabled = true; btn.textContent = 'CHECKING...';
  var res  = await fetch('/api/cf/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pw, totp_code:cod})});
  var data = await res.json();
  btn.disabled = false; btn.textContent = 'UNLOCK';
  if (data.ok) { window.location.href = '/cloudflare'; }
  else { var e = document.getElementById('err'); e.textContent = data.error; e.style.display = 'block'; }
}
document.addEventListener('keydown', function(e) { if (e.key === 'Enter') doLogin(); });
</script>
</body>
</html>"""

CF_MAIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>portman — cloudflare</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#0d0d0f; --surface:#15151a; --border:#2a2a35; --accent:#00e5ff; --accent2:#ff4d6d; --text:#e8e8f0; --muted:#6b6b80; --tcp:#3ddc84; --mono:'JetBrains Mono',monospace; --display:'Syne',sans-serif; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:var(--mono); min-height:100vh; padding:2rem; max-width:860px; margin:0 auto; }
  header { display:flex; align-items:center; gap:1rem; margin-bottom:2rem; border-bottom:1px solid var(--border); padding-bottom:1.5rem; }
  header h1 { font-family:var(--display); font-size:2rem; font-weight:800; color:var(--accent); letter-spacing:-1px; }
  .sub { color:var(--muted); font-size:0.75rem; }
  .back { margin-left:auto; background:none; border:1px solid var(--border); color:var(--muted); border-radius:4px; padding:5px 14px; font-family:var(--mono); font-size:0.72rem; cursor:pointer; text-decoration:none; transition:all 0.15s; }
  .back:hover { border-color:var(--accent); color:var(--accent); }
  .section { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:1.5rem; }
  .section h2 { font-size:0.65rem; text-transform:uppercase; letter-spacing:2px; color:var(--muted); margin-bottom:1.25rem; }
  label { display:block; font-size:0.65rem; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-top:1rem; margin-bottom:0.4rem; }
  label:first-of-type { margin-top:0; }
  input, select { width:100%; background:var(--bg); border:1px solid var(--border); color:var(--text); font-family:var(--mono); font-size:0.85rem; padding:0.6rem 0.8rem; border-radius:4px; outline:none; transition:border-color 0.15s; }
  input:focus, select:focus { border-color:var(--accent); }
  .row { display:grid; grid-template-columns:1fr 1fr; gap:1rem; }
  .btn { background:var(--accent); color:#000; border:none; border-radius:4px; padding:0.6rem 1.25rem; font-family:var(--mono); font-size:0.8rem; font-weight:700; cursor:pointer; letter-spacing:1px; transition:opacity 0.15s; margin-top:1rem; }
  .btn:hover { opacity:0.85; } .btn:disabled { opacity:0.4; cursor:default; }
  .btn-danger { background:none; border:1px solid var(--accent2); color:var(--accent2); border-radius:4px; padding:0.5rem 1rem; font-family:var(--mono); font-size:0.75rem; cursor:pointer; transition:all 0.15s; }
  .btn-danger:hover { background:rgba(255,77,109,0.1); }
  .check { display:flex; align-items:center; gap:0.5rem; font-size:0.8rem; margin-top:0.75rem; }
  .check input { width:auto; padding:0; accent-color:var(--accent); }
  .toast { position:fixed; bottom:2rem; right:2rem; padding:0.75rem 1.25rem; border-radius:5px; font-size:0.8rem; opacity:0; transform:translateY(10px); transition:all 0.2s; pointer-events:none; z-index:999; }
  .toast.show { opacity:1; transform:translateY(0); }
  .toast.ok  { background:rgba(61,220,132,0.15); border:1px solid var(--tcp); color:var(--tcp); }
  .toast.err { background:rgba(255,77,109,0.15); border:1px solid var(--accent2); color:var(--accent2); }
  .status-dot { width:8px; height:8px; border-radius:50%; display:inline-block; margin-right:6px; }
  .dot-ok  { background:var(--tcp); }
  .dot-err { background:var(--accent2); }
  .results { margin-top:1rem; font-size:0.75rem; color:var(--tcp); line-height:1.8; display:none; }
</style>
</head>
<body>
<div id="cf-demo-banner" style="display:none;background:rgba(255,179,71,0.1);border:1px solid rgba(255,179,71,0.4);color:#ffb347;padding:0.6rem 1.25rem;border-radius:6px;font-size:0.75rem;margin-bottom:1rem;text-align:center;letter-spacing:0.5px">
  ⚠ demo mode — read only view. all write operations are disabled.
</div>
<header>
  <h1>cloudflare</h1>
  <span class="sub">DNS record manager</span>
  <a href="/" class="back">← portman</a>
</header>

<!-- API config -->
<div class="section">
  <h2>API configuration
    <span class="status-dot __TOKEN_SET__ __ZONE_ID_SET__" id="cfg-dot"
      style="margin-left:8px"
      class="status-dot"></span>
  </h2>
  <label>API Token <span style="font-size:0.6rem;opacity:0.6">(leave blank to keep existing)</span></label>
  <input type="password" id="api-token" placeholder="Cloudflare API token">
  <div class="row">
    <div>
      <label>Zone ID</label>
      <input type="text" id="zone-id" placeholder="Zone ID from CF dashboard">
    </div>
    <div>
      <label>Zone name <span style="font-size:0.6rem;opacity:0.6">(e.g. linuslinus.com)</span></label>
      <input type="text" id="zone-name" placeholder="yourdomain.com">
    </div>
  </div>
  <button class="btn" onclick="saveConfig()">SAVE CONFIG</button>
</div>

<!-- Live zone records -->
<div class="section">
  <h2 style="display:flex;align-items:center;justify-content:space-between">
    <span>zone dns records</span>
    <span style="display:flex;gap:0.5rem;align-items:center">
      <select id="cf-filter" onchange="filterRecords()" style="width:auto;padding:0.3rem 0.6rem;font-size:0.72rem">
        <option value="all">All</option>
        <option value="minecraft">Minecraft SRV</option>
        <option value="a">A records</option>
        <option value="srv">Other SRV</option>
        <option value="other">Other</option>
      </select>
      <button onclick="loadZoneRecords()" style="background:none;border:1px solid var(--border);color:var(--muted);border-radius:4px;padding:0.3rem 0.75rem;font-family:var(--mono);font-size:0.72rem;cursor:pointer">refresh</button>
    </span>
  </h2>
  <div id="zone-loading" style="color:var(--muted);font-size:0.75rem;padding:0.5rem 0">loading records...</div>
  <table id="zone-table" style="width:100%;border-collapse:collapse;font-size:0.78rem;display:none">
    <thead>
      <tr>
        <th style="text-align:left;padding:0.5rem 0.75rem;font-size:0.62rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);border-bottom:1px solid var(--border)">Type</th>
        <th style="text-align:left;padding:0.5rem 0.75rem;font-size:0.62rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);border-bottom:1px solid var(--border)">Name</th>
        <th style="text-align:left;padding:0.5rem 0.75rem;font-size:0.62rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);border-bottom:1px solid var(--border)">Content</th>
        <th style="text-align:left;padding:0.5rem 0.75rem;font-size:0.62rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);border-bottom:1px solid var(--border)">Label</th>
      </tr>
    </thead>
    <tbody id="zone-body"></tbody>
  </table>
  <div id="zone-empty" style="display:none;color:var(--muted);font-size:0.75rem;padding:0.5rem 0">no records found</div>
  <div id="zone-error" style="display:none;color:var(--accent2);font-size:0.75rem;padding:0.5rem 0"></div>
</div>

<!-- Saved DNS entries -->
<div class="section" id="entries-section" style="display:none">
  <h2>saved server records</h2>
  <div id="entries-list"></div>
</div>

<!-- Create DNS records -->
<div class="section">
  <h2>Create DNS records for a server</h2>
  <label>Label <span style="font-size:0.6rem;opacity:0.6">(display name, e.g. "Survival server")</span></label>
  <input type="text" id="dns-label" placeholder="e.g. Survival server">
  <div class="row" style="margin-top:0">
    <div>
      <label>Subdomain <span style="font-size:0.6rem;opacity:0.6">(e.g. fly)</span></label>
      <input type="text" id="subdomain" placeholder="fly">
    </div>
    <div>
      <label>Linode public IP</label>
      <input type="text" id="linode-ip" placeholder="172.232.147.23">
    </div>
  </div>
  <div class="row">
    <div>
      <label>SRV target <span style="font-size:0.6rem;opacity:0.6">(A record to point SRV at)</span></label>
      <input type="text" id="srv-target" placeholder="srv.linuslinus.com">
    </div>
    <div>
      <label>Java port</label>
      <input type="number" id="java-port" placeholder="25580" min="1" max="65535">
    </div>
  </div>
  <div class="check">
    <input type="checkbox" id="add-udp">
    <label style="margin:0;text-transform:none;letter-spacing:0;font-size:0.8rem;color:var(--text)">Also create UDP SRV (Java)</label>
  </div>
  <div class="check">
    <input type="checkbox" id="add-geyser" onchange="toggleGeyser()">
    <label style="margin:0;text-transform:none;letter-spacing:0;font-size:0.8rem;color:var(--text)">Add Geyser (Bedrock) SRV</label>
  </div>
  <div id="geyser-port-wrap" style="display:none;margin-top:0.75rem">
    <label>Geyser port</label>
    <input type="number" id="geyser-port" placeholder="19132" min="1" max="65535">
  </div>
  <div class="check">
    <input type="checkbox" id="create-portman-rule" onchange="togglePortmanRule()">
    <label style="margin:0;text-transform:none;letter-spacing:0;font-size:0.8rem;color:var(--text)">Also create portman forwarding rule</label>
  </div>
  <div id="portman-rule-wrap" style="display:none;margin-top:0.75rem;padding:0.75rem;border:1px solid rgba(0,229,255,0.15);border-radius:4px;background:rgba(0,229,255,0.03)">
    <div class="row" style="margin-top:0">
      <div>
        <label>Destination IP <span style="font-size:0.6rem;opacity:0.6">(WireGuard peer, e.g. 10.10.0.2)</span></label>
        <input type="text" id="portman-dest-ip" placeholder="10.10.0.2">
      </div>
      <div>
        <label>Destination port</label>
        <input type="number" id="portman-dest-port" placeholder="same as java port" min="1" max="65535">
      </div>
    </div>
  </div>
  <button class="btn" id="dns-btn" onclick="createDNS()">CREATE RECORDS</button>
  <div class="results" id="results"></div>
</div>

<!-- Session -->
<div class="section" style="display:flex;align-items:center;justify-content:space-between">
  <span style="font-size:0.75rem;color:var(--muted)">Session expires in 1 hour</span>
  <button class="btn-danger" onclick="doLogout()">log out</button>
</div>

<div class="toast" id="toast"></div>
<script>

var allZoneRecords = [];

async function loadZoneRecords() {
  document.getElementById('zone-loading').style.display = 'block';
  document.getElementById('zone-table').style.display = 'none';
  document.getElementById('zone-empty').style.display = 'none';
  document.getElementById('zone-error').style.display = 'none';
  var res  = await fetch('/api/cf/zone_records');
  var data = await res.json();
  document.getElementById('zone-loading').style.display = 'none';
  if (!data.ok) {
    var el = document.getElementById('zone-error');
    el.textContent = data.error; el.style.display = 'block'; return;
  }
  allZoneRecords = data.records || [];
  filterRecords();
}

function filterRecords() {
  var filter = document.getElementById('cf-filter').value;
  var rows   = allZoneRecords.filter(function(r) {
    return filter === 'all' || r.category === filter;
  });
  var tbody = document.getElementById('zone-body');
  if (!rows.length) {
    document.getElementById('zone-table').style.display = 'none';
    document.getElementById('zone-empty').style.display = 'block';
    return;
  }
  document.getElementById('zone-empty').style.display = 'none';
  document.getElementById('zone-table').style.display = 'table';

  var catColors = {minecraft:'#00e5ff', a:'#3ddc84', srv:'#ffb347', other:'#6b6b80'};
  tbody.innerHTML = rows.map(function(r) {
    var typeColor = catColors[r.category] || '#6b6b80';
    var labelCell = r.label
      ? '<span style="color:var(--accent);font-size:0.75rem">' + esc(r.label) + '</span>'
      : '<span style="color:var(--muted)">—</span>';
    return '<tr>' +
      '<td style="padding:0.55rem 0.75rem;border-bottom:1px solid var(--border)">' +
        '<span style="background:rgba(0,0,0,0.3);border:1px solid ' + typeColor + ';color:' + typeColor + ';padding:2px 7px;border-radius:3px;font-size:0.65rem;font-weight:700">' + esc(r.type) + '</span>' +
      '</td>' +
      '<td style="padding:0.55rem 0.75rem;border-bottom:1px solid var(--border);color:var(--text);font-size:0.75rem;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(r.name) + '</td>' +
      '<td style="padding:0.55rem 0.75rem;border-bottom:1px solid var(--border);color:var(--muted);font-size:0.75rem;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(r.content) + '</td>' +
      '<td style="padding:0.55rem 0.75rem;border-bottom:1px solid var(--border)">' + labelCell + '</td>' +
    '</tr>';
  }).join('');
}

const TOKEN_SET   = __TOKEN_SET__;
const ZONE_ID_SET = __ZONE_ID_SET__;
const DEMO_MODE   = __DEMO_MODE__;

(function() {
  var dot = document.getElementById('cfg-dot');
  dot.className = 'status-dot ' + (TOKEN_SET && ZONE_ID_SET ? 'dot-ok' : 'dot-err');
  loadEntries();
  loadZoneRecords();
  if (DEMO_MODE) document.getElementById('cf-demo-banner').style.display = 'block';
  fetch('/api/cf/config').then(function(r){return r.json();}).then(function(d){ if(d.ok && d.zone_name) document.getElementById('zone-name').value = d.zone_name; });
})();

function toggleGeyser() {
  document.getElementById('geyser-port-wrap').style.display =
    document.getElementById('add-geyser').checked ? 'block' : 'none';
}

function togglePortmanRule() {
  document.getElementById('portman-rule-wrap').style.display =
    document.getElementById('create-portman-rule').checked ? 'block' : 'none';
}

async function loadEntries() {
  var res  = await fetch('/api/cf/dns');
  var data = await res.json();
  if (!data.ok) return;
  var entries = data.entries || [];
  var section = document.getElementById('entries-section');
  var list    = document.getElementById('entries-list');
  if (!entries.length) { section.style.display = 'none'; return; }
  section.style.display = 'block';
  list.innerHTML = entries.map(function(e, i) {
    var hasCF    = e.cf_record_ids && e.cf_record_ids.length > 0;
    var hasRules = e.portman_keys  && e.portman_keys.length  > 0;
    var tags = '';
    if (hasCF)    tags += '<span style="background:rgba(246,130,31,0.12);border:1px solid rgba(246,130,31,0.4);color:#f6821f;padding:2px 7px;border-radius:3px;font-size:0.62rem;margin-right:0.35rem">CF records: ' + e.cf_record_ids.length + '</span>';
    if (hasRules) tags += '<span style="background:rgba(0,229,255,0.08);border:1px solid rgba(0,229,255,0.3);color:var(--accent);padding:2px 7px;border-radius:3px;font-size:0.62rem">portman rules: ' + e.portman_keys.length + '</span>';

    var details =
      '<div style="margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border);font-size:0.75rem;color:var(--muted);line-height:2">' +
        '<div><span style="color:var(--text)">domain</span> &nbsp;' + esc(e.full_domain) + '</div>' +
        '<div><span style="color:var(--text)">java port</span> &nbsp;' + e.port + (e.add_udp ? ' (TCP+UDP)' : ' (TCP)') + '</div>' +
        (e.geyser_port ? '<div><span style="color:var(--text)">geyser port</span> &nbsp;' + e.geyser_port + '</div>' : '') +
        (e.dest_ip ? '<div><span style="color:var(--text)">dest</span> &nbsp;' + esc(e.dest_ip) + ':' + (e.dest_port || e.port) + '</div>' : '') +
        (hasCF ? '<div style="margin-top:0.5rem"><span style="color:var(--text)">CF record IDs</span><br>' + e.cf_record_ids.map(function(id){return '<span style="font-size:0.68rem;opacity:0.6">'+id+'</span>';}).join('<br>') + '</div>' : '') +
        (hasRules ? '<div style="margin-top:0.5rem"><span style="color:var(--text)">portman keys</span> &nbsp;' + e.portman_keys.join(', ') + '</div>' : '') +
      '</div>' +
      '<div style="display:flex;gap:0.5rem;margin-top:1rem;flex-wrap:wrap">' +
        (hasCF ? '<button onclick="removeEntry('+i+',true,false)" style="background:none;border:1px solid #f6821f;color:#f6821f;border-radius:4px;padding:4px 10px;font-family:var(--mono);font-size:0.68rem;cursor:pointer">delete CF records</button>' : '') +
        (hasRules ? '<button onclick="removeEntry('+i+',false,true)" style="background:none;border:1px solid var(--accent);color:var(--accent);border-radius:4px;padding:4px 10px;font-family:var(--mono);font-size:0.68rem;cursor:pointer">delete portman rules</button>' : '') +
        (hasCF && hasRules ? '<button onclick="removeEntry('+i+',true,true)" style="background:none;border:1px solid var(--accent2);color:var(--accent2);border-radius:4px;padding:4px 10px;font-family:var(--mono);font-size:0.68rem;cursor:pointer">delete everything</button>' : '') +
        '<button onclick="removeEntry('+i+',false,false)" style="background:none;border:1px solid var(--border);color:var(--muted);border-radius:4px;padding:4px 10px;font-family:var(--mono);font-size:0.68rem;cursor:pointer">remove from list only</button>' +
      '</div>';

    return '<div style="border:1px solid var(--border);border-radius:6px;margin-bottom:0.75rem;overflow:hidden">' +
      '<div onclick="toggleEntry(this)" style="display:flex;align-items:center;justify-content:space-between;padding:0.85rem 1rem;cursor:pointer;user-select:none" onmouseover="this.style.background=&quot;rgba(255,255,255,0.02)&quot;" onmouseout="this.style.background=&quot;&quot;">' +
        '<div style="display:flex;align-items:center;gap:0.75rem">' +
          '<span style="color:var(--accent);font-size:0.85rem;font-weight:600">' + esc(e.label) + '</span>' +
          '<span style="color:var(--muted);font-size:0.7rem">#' + esc(e.id || i) + '</span>' +
          tags +
        '</div>' +
        '<span class="entry-chevron" style="color:var(--muted);font-size:0.8rem;transition:transform 0.2s">▼</span>' +
      '</div>' +
      '<div class="entry-body" style="display:none;padding:0 1rem 1rem 1rem">' + details + '</div>' +
    '</div>';
  }).join('');
}

function toggleEntry(header) {
  var body    = header.nextElementSibling;
  var chevron = header.querySelector('.entry-chevron');
  var open    = body.style.display === 'none';
  body.style.display    = open ? 'block' : 'none';
  chevron.style.transform = open ? 'rotate(180deg)' : '';
}

async function removeEntry(i, deleteCF, deleteRules) {
  if (DEMO_MODE) { toast('demo mode — read only', false); return; }
  var msg = deleteCF && deleteRules ? 'Delete CF DNS records AND portman rules?' :
            deleteCF   ? 'Delete CF DNS records? (portman rules kept)' :
            deleteRules ? 'Delete portman rules? (CF records kept)' :
            'Remove from list only? (nothing deleted from CF or portman)';
  if (!confirm(msg)) return;
  var res  = await fetch('/api/cf/dns/' + i, {
    method: 'DELETE',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({delete_cf: !!deleteCF, delete_rules: !!deleteRules})
  });
  var data = await res.json();
  if (data.ok) {
    if (data.results && data.results.length) toast(data.results.length + ' item(s) deleted', true);
    else toast('removed from list', true);
    if (data.errors && data.errors.length) toast('errors: ' + data.errors.join(', '), false);
    loadEntries();
    if (deleteRules) loadZoneRecords();
  } else toast(data.error || 'error', false);
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function saveConfig() {
  if (DEMO_MODE) { toast('demo mode — read only', false); return; }
  var payload = {
    api_token: document.getElementById('api-token').value.trim(),
    zone_id:   document.getElementById('zone-id').value.trim(),
    zone_name: document.getElementById('zone-name').value.trim(),
  };
  var res  = await fetch('/api/cf/config', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
  var data = await res.json();
  toast(data.ok ? 'config saved' : (data.error || 'error'), data.ok);
  if (data.ok) document.getElementById('api-token').value = '';
}

async function createDNS() {
  if (DEMO_MODE) { toast('demo mode — read only', false); return; }
  var label       = document.getElementById('dns-label').value.trim();
  var subdomain   = document.getElementById('subdomain').value.trim();
  var linodeIp    = document.getElementById('linode-ip').value.trim();
  var srvTarget   = document.getElementById('srv-target').value.trim();
  var javaPort    = parseInt(document.getElementById('java-port').value);
  var addUdp      = document.getElementById('add-udp').checked;
  var addGeyser   = document.getElementById('add-geyser').checked;
  var geyserPort  = addGeyser ? parseInt(document.getElementById('geyser-port').value) : 0;
  var zoneName    = document.getElementById('zone-name').value.trim();
  var createRule  = document.getElementById('create-portman-rule').checked;
  var destIp      = createRule ? document.getElementById('portman-dest-ip').value.trim() : '';
  var destPort    = createRule ? parseInt(document.getElementById('portman-dest-port').value || javaPort) : 0;

  if (!subdomain || !linodeIp || !srvTarget || !javaPort) { toast('fill in all required fields', false); return; }
  if (createRule && !destIp) { toast('enter destination IP for portman rule', false); return; }

  var fullDomain = subdomain + (zoneName ? '.' + zoneName : '');
  var btn = document.getElementById('dns-btn');
  btn.disabled = true; btn.textContent = 'CREATING...';

  var res = await fetch('/api/cf/dns', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      label: label, subdomain: subdomain, full_domain: fullDomain,
      linode_ip: linodeIp, srv_target: srvTarget,
      port: javaPort, add_udp: addUdp, geyser_port: geyserPort,
      create_portman_rule: createRule, dest_ip: destIp, dest_port: destPort || javaPort
    })
  });
  var data = await res.json();
  btn.disabled = false; btn.textContent = 'CREATE RECORDS';

  if (data.ok || data.partial) {
    var wrap = document.getElementById('results');
    wrap.innerHTML = (data.results || []).map(function(r) { return '✓ ' + r; }).join('<br>');
    wrap.style.display = 'block';
    toast(data.ok ? 'records created' : 'partial success — check results', data.ok);
    if (data.ok) { loadEntries(); loadZoneRecords(); }
  } else {
    toast(data.error || 'error', false);
  }
}

async function doLogout() {
  await fetch('/api/cf/logout', {method:'POST'});
  window.location.href = '/cloudflare';
}

function toast(msg, ok) {
  var t = document.getElementById('toast');
  t.textContent = msg; t.className = 'toast show ' + (ok ? 'ok' : 'err');
  setTimeout(function() { t.className = 'toast'; }, 3000);
}
</script>
</body>
</html>"""

# ── Main page HTML ────────────────────────────────────────────────────────────

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>portman</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0d0d0f;
    --surface: #15151a;
    --border: #2a2a35;
    --accent: #00e5ff;
    --accent2: #ff4d6d;
    --text: #e8e8f0;
    --muted: #6b6b80;
    --tcp: #3ddc84;
    --udp: #ffb347;
    --mono: 'JetBrains Mono', monospace;
    --display: 'Syne', sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--mono); min-height: 100vh; padding: 2rem; }

  header {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1.5rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
  }
  header h1 { font-family: var(--display); font-size: 2rem; font-weight: 800; color: var(--accent); letter-spacing: -1px; }
  header .subtitle { color: var(--muted); font-size: 0.8rem; }
  .header-btns { margin-left: auto; display: flex; gap: 0.5rem; }
  .btn-settings, .btn-cf {
    background: none;
    border: 1px solid var(--border);
    color: var(--muted);
    border-radius: 4px;
    padding: 5px 14px;
    font-family: var(--mono);
    font-size: 0.72rem;
    cursor: pointer;
    transition: all 0.15s;
    letter-spacing: 0.5px;
    text-decoration: none;
    display: inline-block;
  }
  .btn-settings:hover, .btn-settings.active { border-color: var(--accent); color: var(--accent); }
  .btn-cf:hover { border-color: #f6821f; color: #f6821f; }

  .settings-bar {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem 1.25rem;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
  }
  .settings-bar .s-label { font-size: 0.68rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; white-space: nowrap; }
  .settings-bar input { flex: 1; min-width: 200px; max-width: 320px; }
  .btn-save {
    background: none;
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 4px;
    padding: 0.55rem 1.1rem;
    font-family: var(--mono);
    font-size: 0.75rem;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
  }
  .btn-save:hover { border-color: var(--accent); color: var(--accent); }

  .grid { display: grid; grid-template-columns: 1fr 380px; gap: 2rem; align-items: start; }
  @media(max-width: 1100px) { .grid { grid-template-columns: 1fr; } }

  .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
  .panel-header {
    padding: 1rem 1.25rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--muted);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .rule-count { background: var(--border); color: var(--accent); padding: 2px 8px; border-radius: 999px; font-size: 0.7rem; }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left;
    padding: 0.65rem 1.25rem;
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  td { padding: 0.75rem 1.25rem; border-bottom: 1px solid var(--border); font-size: 0.82rem; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr { transition: background 0.15s; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .col-label { max-width: 150px; }
  .col-domain { max-width: 200px; }
  .label-text { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
  .domain-wrap { display: flex; align-items: center; gap: 0.35rem; overflow: hidden; }
  .domain-text { color: var(--accent); font-size: 0.78rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .ssl-lock { color: var(--tcp); font-size: 0.7rem; flex-shrink: 0; }
  .muted-dash { color: var(--muted); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.65rem; font-weight: 700; letter-spacing: 1px; }
  .badge-udp { background: rgba(255,179,71,0.15); color: var(--udp); border: 1px solid rgba(255,179,71,0.3); }
  .badge-tcp { background: rgba(61,220,132,0.15); color: var(--tcp); border: 1px solid rgba(61,220,132,0.3); }
  .dest { color: var(--accent); }
  .actions { white-space: nowrap; }
  .btn-edit {
    background: none; border: 1px solid var(--accent); color: var(--accent);
    border-radius: 4px; padding: 4px 10px; font-family: var(--mono);
    font-size: 0.7rem; cursor: pointer; transition: background 0.15s; margin-right: 0.35rem;
  }
  .btn-edit:hover { background: rgba(0,229,255,0.1); }
  .btn-remove {
    background: none; border: 1px solid var(--accent2); color: var(--accent2);
    border-radius: 4px; padding: 4px 10px; font-family: var(--mono);
    font-size: 0.7rem; cursor: pointer; transition: background 0.15s;
  }
  .btn-remove:hover { background: rgba(255,77,109,0.15); }
  .empty-row td { color: var(--muted); text-align: center; padding: 2.5rem; font-size: 0.8rem; }

  .form-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1.5rem; }
  .form-panel h2 { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 2px; color: var(--muted); margin-bottom: 1.5rem; transition: color 0.15s; }
  .form-panel h2.edit-mode { color: var(--accent); }
  label { display: block; font-size: 0.68rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 0.4rem; margin-top: 1rem; }
  label:first-of-type { margin-top: 0; }
  .optional { font-size: 0.6rem; text-transform: none; letter-spacing: 0; opacity: 0.6; }
  input, select {
    width: 100%; background: var(--bg); border: 1px solid var(--border);
    color: var(--text); font-family: var(--mono); font-size: 0.85rem;
    padding: 0.6rem 0.8rem; border-radius: 4px; outline: none; transition: border-color 0.15s;
  }
  input:focus, select:focus { border-color: var(--accent); }
  select option { background: var(--bg); }

  .ssl-option {
    margin-top: 0.75rem;
    padding: 0.6rem 0.8rem;
    border: 1px solid rgba(0,229,255,0.2);
    border-radius: 4px;
    background: rgba(0,229,255,0.04);
  }
  .ssl-option label {
    display: flex; align-items: center; gap: 0.5rem;
    cursor: pointer; text-transform: none; letter-spacing: 0;
    font-size: 0.8rem; color: var(--accent); margin: 0;
  }
  .ssl-option input[type=checkbox] {
    width: auto; padding: 0; border: none; background: none;
    cursor: pointer; accent-color: var(--accent);
  }

  .btn-add {
    margin-top: 1.5rem; width: 100%; background: var(--accent); color: #000;
    border: none; border-radius: 4px; padding: 0.75rem; font-family: var(--mono);
    font-size: 0.85rem; font-weight: 700; cursor: pointer; letter-spacing: 1px; transition: opacity 0.15s;
  }
  .btn-add:hover { opacity: 0.85; }
  .btn-add:disabled { opacity: 0.4; cursor: default; }
  .cancel-link {
    display: block; text-align: center; margin-top: 0.75rem;
    font-size: 0.72rem; color: var(--muted); text-decoration: none; cursor: pointer; letter-spacing: 0.5px;
  }
  .cancel-link:hover { color: var(--text); }

  .toast {
    position: fixed; bottom: 2rem; right: 2rem; padding: 0.75rem 1.25rem;
    border-radius: 5px; font-size: 0.8rem; opacity: 0; transform: translateY(10px);
    transition: all 0.2s; pointer-events: none; z-index: 999;
  }
  .toast.show { opacity: 1; transform: translateY(0); }
  .toast.ok  { background: rgba(61,220,132,0.15); border: 1px solid var(--tcp); color: var(--tcp); }
  .toast.err { background: rgba(255,77,109,0.15); border: 1px solid var(--accent2); color: var(--accent2); }
</style>
</head>
<body>

<div id="demo-banner" style="display:none;background:rgba(255,179,71,0.1);border:1px solid rgba(255,179,71,0.4);color:#ffb347;padding:0.6rem 1.25rem;border-radius:6px;font-size:0.75rem;margin-bottom:1rem;text-align:center;letter-spacing:0.5px">
  ⚠ demo mode — read only view. all write operations are disabled.
</div>
<header>
  <h1>portman</h1>
  <span class="subtitle">iptables DNAT manager &mdash; """ + (DEFAULT_DEST_IP or "set DEST_IP env") + """</span>
  <div class="header-btns">
    <button class="btn-settings" id="settings-btn" onclick="toggleSettings()">settings</button>
    <a href="/cloudflare" class="btn-cf" id="cf-btn" style="display:none">cloudflare</a>
  </div>
</header>

<div class="settings-bar" id="settings-bar" style="display:none">
  <span class="s-label">Certbot email</span>
  <input type="email" id="certbot-email" placeholder="admin@example.com">
  <button class="btn-save" onclick="saveSettings()">Save</button>
</div>

<div class="grid">
  <div class="panel">
    <div class="panel-header">
      <span>active forwarding rules</span>
      <span class="rule-count" id="count">0</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Label</th>
          <th>Domain</th>
          <th>Proto</th>
          <th>Incoming port</th>
          <th>Destination</th>
          <th></th>
        </tr>
      </thead>
      <tbody id="rules-body">
        <tr class="empty-row"><td colspan="6">loading...</td></tr>
      </tbody>
    </table>
  </div>

  <div class="form-panel">
    <h2 id="form-title">add forwarding rule</h2>

    <label>Label <span class="optional">(optional)</span></label>
    <input type="text" id="label" placeholder="e.g. Minecraft Server" autocomplete="off">

    <label>Domain / Subdomain <span class="optional">(optional)</span></label>
    <input type="text" id="domain" placeholder="e.g. mc.example.com" autocomplete="off" oninput="onDomainInput()">

    <div class="ssl-option" id="ssl-option" style="display:none">
      <label>
        <input type="checkbox" id="ssl-enabled">
        Request SSL certificate
      </label>
    </div>

    <label>Protocol</label>
    <select id="proto">
      <option value="udp">UDP</option>
      <option value="tcp">TCP</option>
    </select>

    <label>Incoming port (on this VPS)</label>
    <input type="number" id="src_port" placeholder="e.g. 27015" min="1" max="65535">

    <label>Destination IP</label>
    <input type="text" id="dest_ip" placeholder="e.g. 10.0.0.2" value=\"""" + DEFAULT_DEST_IP + """\">

    <label>Destination port</label>
    <input type="number" id="dest_port" placeholder="e.g. 27015" min="1" max="65535">

    <button class="btn-add" id="add-btn" onclick="submitRule()">ADD RULE</button>
    <a href="#" class="cancel-link" id="cancel-edit" onclick="cancelEdit(); return false;" style="display:none">cancel edit</a>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const DEFAULT_DEST_IP = '""" + DEFAULT_DEST_IP + """';
const CF_ENABLED = __CF_ENABLED__;
const DEMO_MODE  = __DEMO_MODE__;

let rules    = [];
let editMode = false;
let editIdx  = -1;

async function init() {
  await Promise.all([loadRules(), loadSettings()]);
  if (CF_ENABLED) document.getElementById('cf-btn').style.display = 'inline-block';
  if (DEMO_MODE) {
    document.getElementById('demo-banner').style.display = 'block';
    // Disable all write buttons
    document.getElementById('add-btn').disabled = true;
    document.getElementById('add-btn').title = 'demo mode — read only';
  }
}

function toggleSettings() {
  var bar = document.getElementById('settings-bar');
  var btn = document.getElementById('settings-btn');
  var open = bar.style.display === 'none';
  bar.style.display = open ? 'flex' : 'none';
  btn.classList.toggle('active', open);
}

async function loadSettings() {
  var res = await fetch('/api/settings');
  var s   = await res.json();
  document.getElementById('certbot-email').value = s.certbot_email || '';
}

async function saveSettings() {
  if (DEMO_MODE) { toast('demo mode — read only', false); return; }
  var email = document.getElementById('certbot-email').value.trim();
  var res   = await fetch('/api/settings', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({certbot_email: email})
  });
  var data = await res.json();
  toast(data.ok ? 'settings saved' : (data.error || 'error'), data.ok);
}

async function loadRules() {
  var res = await fetch('/api/rules');
  rules = await res.json();
  render();
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function labelCell(r) {
  return r.label
    ? '<span class="label-text">' + escHtml(r.label) + '</span>'
    : '<span class="muted-dash">&mdash;</span>';
}

function domainCell(r) {
  if (!r.domain) return '<span class="muted-dash">&mdash;</span>';
  var lock = r.ssl_active ? '<span class="ssl-lock" title="SSL active">&#128274;</span>' : '';
  return '<div class="domain-wrap"><span class="domain-text">' + escHtml(r.domain) + '</span>' + lock + '</div>';
}

function render() {
  var body = document.getElementById('rules-body');
  document.getElementById('count').textContent = rules.length;
  if (!rules.length) {
    body.innerHTML = '<tr class="empty-row"><td colspan="6">no rules configured</td></tr>';
    return;
  }
  body.innerHTML = rules.map(function(r, i) {
    return '<tr>' +
      '<td class="col-label">' + labelCell(r) + '</td>' +
      '<td class="col-domain">' + domainCell(r) + '</td>' +
      '<td><span class="badge badge-' + r.proto + '">' + r.proto.toUpperCase() + '</span></td>' +
      '<td>:' + r.src_port + '</td>' +
      '<td class="dest">' + escHtml(r.dest_ip) + ':' + r.dest_port + '</td>' +
      '<td class="actions">' +
        '<button class="btn-edit" onclick="startEdit(' + i + ')">edit</button>' +
        '<button class="btn-remove" onclick="removeRule(' + i + ')">remove</button>' +
      '</td>' +
    '</tr>';
  }).join('');
}

function onDomainInput() {
  var val = document.getElementById('domain').value.trim();
  document.getElementById('ssl-option').style.display = val ? 'block' : 'none';
  if (!val) document.getElementById('ssl-enabled').checked = false;
}

function startEdit(i) {
  var r = rules[i];
  editMode = true;
  editIdx  = i;
  document.getElementById('label').value    = r.label  || '';
  document.getElementById('domain').value   = r.domain || '';
  document.getElementById('proto').value    = r.proto;
  document.getElementById('src_port').value = r.src_port;
  document.getElementById('dest_ip').value  = r.dest_ip;
  document.getElementById('dest_port').value = r.dest_port;
  document.getElementById('ssl-enabled').checked = false;
  document.getElementById('ssl-option').style.display = r.domain ? 'block' : 'none';
  var title = document.getElementById('form-title');
  title.textContent = 'edit rule';
  title.classList.add('edit-mode');
  document.getElementById('add-btn').textContent = 'UPDATE RULE';
  document.getElementById('cancel-edit').style.display = 'block';
  document.querySelector('.form-panel').scrollIntoView({behavior: 'smooth'});
}

function cancelEdit() {
  editMode = false;
  editIdx  = -1;
  var title = document.getElementById('form-title');
  title.textContent = 'add forwarding rule';
  title.classList.remove('edit-mode');
  document.getElementById('add-btn').textContent = 'ADD RULE';
  document.getElementById('cancel-edit').style.display = 'none';
  document.getElementById('ssl-option').style.display = 'none';
  document.getElementById('ssl-enabled').checked = false;
  document.getElementById('proto').value    = 'udp';
  document.getElementById('src_port').value = '';
  document.getElementById('dest_ip').value  = DEFAULT_DEST_IP;
  document.getElementById('dest_port').value = '';
  document.getElementById('label').value    = '';
  document.getElementById('domain').value   = '';
}

async function submitRule() {
  if (DEMO_MODE) { toast('demo mode — read only', false); return; }
  var proto     = document.getElementById('proto').value;
  var src_port  = parseInt(document.getElementById('src_port').value);
  var dest_ip   = document.getElementById('dest_ip').value.trim();
  var dest_port = parseInt(document.getElementById('dest_port').value);
  var label     = document.getElementById('label').value.trim();
  var domain    = document.getElementById('domain').value.trim();
  var wantSsl   = document.getElementById('ssl-enabled').checked;

  if (!src_port || !dest_ip || !dest_port) { toast('fill in required fields', false); return; }

  var btn = document.getElementById('add-btn');
  btn.disabled = true;
  btn.textContent = editMode ? 'UPDATING...' : 'ADDING...';

  var res;
  if (editMode) {
    var old = rules[editIdx];
    res = await fetch('/api/rules', {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        old_proto: old.proto, old_src_port: old.src_port,
        old_dest_ip: old.dest_ip, old_dest_port: old.dest_port,
        new_proto: proto, new_src_port: src_port,
        new_dest_ip: dest_ip, new_dest_port: dest_port,
        label: label, domain: domain
      })
    });
  } else {
    res = await fetch('/api/rules', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({proto: proto, src_port: src_port, dest_ip: dest_ip, dest_port: dest_port, label: label, domain: domain})
    });
  }

  var data = await res.json();
  btn.disabled = false;
  btn.textContent = editMode ? 'UPDATE RULE' : 'ADD RULE';

  if (data.ok) {
    toast(editMode ? 'rule updated' : 'rule added', true);
    if (editMode) cancelEdit();
    loadRules();
    if (wantSsl && domain) requestCert(domain);
  } else {
    toast(data.error || 'error', false);
  }
}

async function requestCert(domain) {
  toast('requesting ssl certificate\u2026', true);
  var res = await fetch('/api/ssl', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({domain: domain})
  });
  var data = await res.json();
  toast(data.ok ? 'ssl active for ' + domain : 'ssl: ' + (data.error || 'error'), data.ok);
  if (data.ok) loadRules();
}

async function removeRule(i) {
  if (DEMO_MODE) { toast('demo mode — read only', false); return; }
  var r = rules[i];
  if (!confirm('Remove ' + r.proto.toUpperCase() + ' :' + r.src_port + ' \u2192 ' + r.dest_ip + ':' + r.dest_port + '?')) return;
  var res = await fetch('/api/rules', {
    method: 'DELETE',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({proto: r.proto, src_port: r.src_port, dest_ip: r.dest_ip, dest_port: r.dest_port})
  });
  var data = await res.json();
  if (data.ok) { toast('rule removed', true); loadRules(); }
  else toast(data.error || 'error', false);
}

function toast(msg, ok) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + (ok ? 'ok' : 'err');
  setTimeout(function() { t.className = 'toast'; }, 3000);
}

init();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
