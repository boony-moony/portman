#!/usr/bin/env python3
"""
portman - iptables DNAT port forwarding manager
Reads existing rules, lets you add/remove via web UI
"""

import subprocess
import re
import json
import os
from functools import wraps
from flask import Flask, request, jsonify, Response, session, redirect, url_for
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-production")
auth = HTTPBasicAuth()

# --- Config ---
USERNAME = os.environ.get("PORTMAN_USER", "admin")
PASSWORD_HASH = generate_password_hash(os.environ.get("PORTMAN_PASS", "admin"))
# The internal IP to forward to (your TrueNAS IP)
DEFAULT_DEST_IP = os.environ.get("DEST_IP", "")
# The network interface facing the internet (e.g. eth0)
WAN_IFACE = os.environ.get("WAN_IFACE", "eth0")

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

def get_existing_rules():
    """Parse existing DNAT rules from iptables -t nat -L PREROUTING -n --line-numbers"""
    rules = []
    try:
        output = run("iptables -t nat -L PREROUTING -n --line-numbers")
        for line in output.splitlines():
            # Match both numeric (6/17) and named (tcp/udp) protocol formats
            m = re.match(
                r'(\d+)\s+DNAT\s+(\w+)\s+--\s+\S+\s+\S+\s+\S+\s+dpt:(\d+)\s+to:([^:]+):(\d+)',
                line.strip()
            )
            if m:
                proto_raw = m.group(2)
                proto = PROTO_MAP.get(proto_raw, proto_raw)
                if proto not in ("tcp", "udp"):
                    continue
                rules.append({
                    "line": int(m.group(1)),
                    "proto": proto,
                    "src_port": int(m.group(3)),
                    "dest_ip": m.group(4),
                    "dest_port": int(m.group(5)),
                })
    except Exception as e:
        print(f"Error reading iptables: {e}")
    return rules

def add_rule(proto, src_port, dest_ip, dest_port):
    """Add DNAT + FORWARD + MASQUERADE rule and persist"""
    run(f"iptables -t nat -A PREROUTING -i {WAN_IFACE} -p {proto} --dport {src_port} -j DNAT --to-destination {dest_ip}:{dest_port}")
    run(f"iptables -A FORWARD -p {proto} -d {dest_ip} --dport {dest_port} -j ACCEPT")
    run(f"iptables -t nat -A POSTROUTING -p {proto} -d {dest_ip} --dport {dest_port} -j MASQUERADE")
    persist()

def remove_rule(proto, src_port, dest_ip, dest_port):
    """Remove DNAT + FORWARD + MASQUERADE rule and persist"""
    run(f"iptables -t nat -D PREROUTING -i {WAN_IFACE} -p {proto} --dport {src_port} -j DNAT --to-destination {dest_ip}:{dest_port}", check=False)
    run(f"iptables -D FORWARD -p {proto} -d {dest_ip} --dport {dest_port} -j ACCEPT", check=False)
    run(f"iptables -t nat -D POSTROUTING -p {proto} -d {dest_ip} --dport {dest_port} -j MASQUERADE", check=False)
    persist()

def persist():
    """Save rules so they survive reboot"""
    # Try iptables-save to file (works on Debian/Ubuntu Linode images)
    try:
        run("iptables-save > /etc/iptables/rules.v4")
    except Exception:
        try:
            run("iptables-save > /etc/iptables.rules")
        except Exception:
            pass  # Best effort

# ── Routes ──────────────────────────────────────────────────────────────────

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
        proto    = data["proto"].lower()
        src_port = int(data["src_port"])
        dest_ip  = data["dest_ip"].strip()
        dest_port= int(data["dest_port"])
        assert proto in ("tcp", "udp")
        assert 1 <= src_port <= 65535
        assert 1 <= dest_port <= 65535
        add_rule(proto, src_port, dest_ip, dest_port)
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
        remove_rule(proto, src_port, dest_ip, dest_port)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

# ── Embedded HTML ────────────────────────────────────────────────────────────

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
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    min-height: 100vh;
    padding: 2rem;
  }
  header {
    display: flex;
    align-items: baseline;
    gap: 1rem;
    margin-bottom: 2.5rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
  }
  header h1 {
    font-family: var(--display);
    font-size: 2rem;
    font-weight: 800;
    color: var(--accent);
    letter-spacing: -1px;
  }
  header span {
    color: var(--muted);
    font-size: 0.8rem;
  }
  .grid { display: grid; grid-template-columns: 1fr 380px; gap: 2rem; align-items: start; }
  @media(max-width: 900px) { .grid { grid-template-columns: 1fr; } }

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
  }
  td { padding: 0.85rem 1.25rem; border-bottom: 1px solid var(--border); font-size: 0.82rem; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr { transition: background 0.15s; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 1px;
  }
  .badge-udp { background: rgba(255,179,71,0.15); color: var(--udp); border: 1px solid rgba(255,179,71,0.3); }
  .badge-tcp { background: rgba(61,220,132,0.15); color: var(--tcp); border: 1px solid rgba(61,220,132,0.3); }
  .arrow { color: var(--muted); margin: 0 0.4rem; }
  .dest { color: var(--accent); }
  .btn-remove {
    background: none;
    border: 1px solid var(--accent2);
    color: var(--accent2);
    border-radius: 4px;
    padding: 4px 10px;
    font-family: var(--mono);
    font-size: 0.7rem;
    cursor: pointer;
    transition: background 0.15s;
  }
  .btn-remove:hover { background: rgba(255,77,109,0.15); }
  .empty-row td { color: var(--muted); text-align: center; padding: 2.5rem; font-size: 0.8rem; }

  /* Form */
  .form-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1.5rem; }
  .form-panel h2 {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--muted);
    margin-bottom: 1.5rem;
  }
  label { display: block; font-size: 0.68rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 0.4rem; margin-top: 1rem; }
  label:first-of-type { margin-top: 0; }
  input, select {
    width: 100%;
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    font-family: var(--mono);
    font-size: 0.85rem;
    padding: 0.6rem 0.8rem;
    border-radius: 4px;
    outline: none;
    transition: border-color 0.15s;
  }
  input:focus, select:focus { border-color: var(--accent); }
  select option { background: var(--bg); }
  .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
  .btn-add {
    margin-top: 1.5rem;
    width: 100%;
    background: var(--accent);
    color: #000;
    border: none;
    border-radius: 4px;
    padding: 0.75rem;
    font-family: var(--mono);
    font-size: 0.85rem;
    font-weight: 700;
    cursor: pointer;
    letter-spacing: 1px;
    transition: opacity 0.15s;
  }
  .btn-add:hover { opacity: 0.85; }
  .btn-add:disabled { opacity: 0.4; cursor: default; }
  .toast {
    position: fixed;
    bottom: 2rem;
    right: 2rem;
    padding: 0.75rem 1.25rem;
    border-radius: 5px;
    font-size: 0.8rem;
    opacity: 0;
    transform: translateY(10px);
    transition: all 0.2s;
    pointer-events: none;
    z-index: 999;
  }
  .toast.show { opacity: 1; transform: translateY(0); }
  .toast.ok { background: rgba(61,220,132,0.15); border: 1px solid var(--tcp); color: var(--tcp); }
  .toast.err { background: rgba(255,77,109,0.15); border: 1px solid var(--accent2); color: var(--accent2); }
</style>
</head>
<body>
<header>
  <h1>portman</h1>
  <span>iptables DNAT manager — """ + (DEFAULT_DEST_IP or "set DEST_IP env") + """</span>
</header>

<div class="grid">
  <div class="panel">
    <div class="panel-header">
      <span>active forwarding rules</span>
      <span class="rule-count" id="count">0</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Proto</th>
          <th>Incoming port</th>
          <th>Destination</th>
          <th></th>
        </tr>
      </thead>
      <tbody id="rules-body">
        <tr class="empty-row"><td colspan="4">loading...</td></tr>
      </tbody>
    </table>
  </div>

  <div class="form-panel">
    <h2>add forwarding rule</h2>
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

    <button class="btn-add" id="add-btn" onclick="addRule()">ADD RULE</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let rules = [];

async function loadRules() {
  const res = await fetch('/api/rules');
  rules = await res.json();
  render();
}

function render() {
  const body = document.getElementById('rules-body');
  document.getElementById('count').textContent = rules.length;
  if (!rules.length) {
    body.innerHTML = '<tr class="empty-row"><td colspan="4">no rules configured</td></tr>';
    return;
  }
  body.innerHTML = rules.map(r => `
    <tr>
      <td><span class="badge badge-${r.proto}">${r.proto.toUpperCase()}</span></td>
      <td>:${r.src_port}</td>
      <td class="dest">${r.dest_ip}:${r.dest_port}</td>
      <td><button class="btn-remove" onclick="removeRule('${r.proto}',${r.src_port},'${r.dest_ip}',${r.dest_port})">remove</button></td>
    </tr>
  `).join('');
}

async function addRule() {
  const proto     = document.getElementById('proto').value;
  const src_port  = parseInt(document.getElementById('src_port').value);
  const dest_ip   = document.getElementById('dest_ip').value.trim();
  const dest_port = parseInt(document.getElementById('dest_port').value);

  if (!src_port || !dest_ip || !dest_port) { toast('fill in all fields', false); return; }

  const btn = document.getElementById('add-btn');
  btn.disabled = true;
  btn.textContent = 'ADDING...';

  const res = await fetch('/api/rules', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({proto, src_port, dest_ip, dest_port})
  });
  const data = await res.json();
  btn.disabled = false;
  btn.textContent = 'ADD RULE';

  if (data.ok) {
    toast('rule added', true);
    loadRules();
  } else {
    toast(data.error || 'error', false);
  }
}

async function removeRule(proto, src_port, dest_ip, dest_port) {
  if (!confirm(`Remove ${proto.toUpperCase()} :${src_port} → ${dest_ip}:${dest_port}?`)) return;
  const res = await fetch('/api/rules', {
    method: 'DELETE',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({proto, src_port, dest_ip, dest_port})
  });
  const data = await res.json();
  if (data.ok) { toast('rule removed', true); loadRules(); }
  else toast(data.error || 'error', false);
}

function toast(msg, ok) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + (ok ? 'ok' : 'err');
  setTimeout(() => t.className = 'toast', 2500);
}

loadRules();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
