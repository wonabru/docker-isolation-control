"""Przykładowy workload: czyta dane pacjentów z /data, wysyła tylko zagregowane statystyki."""
import csv
import json
import urllib.request
from pathlib import Path

rows = []
for f in sorted(Path("/data").glob("*.csv")):
    with open(f, newline="") as fh:
        rows += list(csv.DictReader(fh))

summary = {"records": len(rows), "avg_age": round(sum(int(r["wiek"]) for r in rows) / max(len(rows), 1))}

req = urllib.request.Request("https://httpbin.org/anything", data=json.dumps(summary).encode(),
                             method="POST", headers={"content-type": "application/json"})
with urllib.request.urlopen(req, timeout=30) as r:
    print("wysłano:", summary, "status:", r.status)

Path("/srv/out/summary.json").write_text(json.dumps(summary))
