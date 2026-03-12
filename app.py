#!/usr/bin/env python3
"""
portman - iptables DNAT port forwarding manager
Reads existing rules, lets you add/edit/remove via web UI
Supports optional label and domain/subdomain per rule
Automatically manages nginx reverse proxy configs; optional SSL via certbot
"""

import subprocess
import re
import json
import os
from flask import Flask, request, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-production")
auth = HTTPBasicAuth()

# --- Config ---
USERNAME = os.environ.get("PORTMAN_USER", "admin")
PASSWORD_HASH = generate_password_hash(os.environ.get("PORTMAN_PASS", "admin"))
DEFAULT_DEST_IP = os.environ.get("DEST_IP", "")
WAN_IFACE = os.environ.get("WAN_IFACE", "eth0")

LABELS_FILE   = "/opt/portman/labels.json"
SETTINGS_FILE = "/opt/portman/settings.json"
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
        return {"certbot_email": ""}

def save_settings(settings):
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        print(f"Error saving settings: {e}")

# ── nginx helpers ────────────────────────────────────────────────────────────

def _valid_domain(domain):
    """Basic domain validation to prevent command/path injection."""
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
    rules = []
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

# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
@auth.login_required
def index():
    return HTML_PAGE

@app.route("/api/rules", methods=["GET"])
@auth.login_required
def api_rules():
    return jsonify(get_existing_rules())

@app.route("/api/rules", methods=["POST"])
@auth.login_required
def api_add():
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

        # Get old domain before we overwrite labels
        labels   = load_labels()
        old_key  = label_key(old_proto, old_src_port)
        old_domain = labels.get(old_key, {}).get("domain", "")

        remove_rule(old_proto, old_src_port, old_dest_ip, old_dest_port)
        add_rule(new_proto, new_src_port, new_dest_ip, new_dest_port)

        if old_key in labels:
            del labels[old_key]
        labels[label_key(new_proto, new_src_port)] = {"label": label, "domain": new_domain}
        save_labels(labels)

        # Update nginx: remove old config if domain changed
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
    data = request.json
    settings = load_settings()
    if "certbot_email" in data:
        settings["certbot_email"] = data["certbot_email"].strip()
    save_settings(settings)
    return jsonify({"ok": True})

@app.route("/api/ssl", methods=["POST"])
@auth.login_required
def api_ssl():
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

# ── Embedded HTML ─────────────────────────────────────────────────────────────

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
  .btn-settings {
    margin-left: auto;
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
  }
  .btn-settings:hover, .btn-settings.active { border-color: var(--accent); color: var(--accent); }

  /* Settings bar */
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

  /* Grid */
  .grid { display: grid; grid-template-columns: 1fr 380px; gap: 2rem; align-items: start; }
  @media(max-width: 1100px) { .grid { grid-template-columns: 1fr; } }

  /* Table */
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

  /* Form */
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

  /* SSL option */
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
  .ssl-status { font-size: 0.72rem; color: var(--tcp); margin-top: 0.5rem; display: none; }

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

<header>
  <h1>portman</h1>
  <span class="subtitle">iptables DNAT manager &mdash; """ + (DEFAULT_DEST_IP or "set DEST_IP env") + """</span>
  <button class="btn-settings" id="settings-btn" onclick="toggleSettings()">settings</button>
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

let rules    = [];
let editMode = false;
let editIdx  = -1;

// ── Init ──────────────────────────────────────────────────────────────────
async function init() {
  await Promise.all([loadRules(), loadSettings()]);
}

// ── Settings ──────────────────────────────────────────────────────────────
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
  var email = document.getElementById('certbot-email').value.trim();
  var res   = await fetch('/api/settings', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({certbot_email: email})
  });
  var data = await res.json();
  toast(data.ok ? 'settings saved' : (data.error || 'error'), data.ok);
}

// ── Rules ─────────────────────────────────────────────────────────────────
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

// ── Form helpers ──────────────────────────────────────────────────────────
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

// ── Submit ────────────────────────────────────────────────────────────────
async function submitRule() {
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

// ── Remove ────────────────────────────────────────────────────────────────
async function removeRule(i) {
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

// ── Toast ─────────────────────────────────────────────────────────────────
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
