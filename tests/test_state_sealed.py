import json

from poi import canonical as c
from poi.policy import config_violations, parse
from poi.seal.sealer import Sealer, is_sealed
from poi.state import StateTracker, config_doc

from helpers import ENGINE_IMAGE, ENGINE_MOUNTS, POLICY, FakeFS

INFO = {"client_pub": "c" * 64, "run_pub": "r" * 64, "mounts": {"/data": "d" * 64}, "swap": False,
        "out_target": "/srv/out"}
SEALED_HC = {"ReadonlyRootfs": True, "LogConfig": {"Type": "none"}, "Tmpfs": {"/tmp": ""}}


def test_output_sealed_config_section_and_tmpfs_excluded(tmp_path):
    fs = FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS)
    fs.host_extra = SEALED_HC
    fs.write("/tmp", None)
    fs.write("/tmp/scratch", b"85010112345")
    out = tmp_path / "out"
    out.mkdir()
    (out / "result.json").write_bytes(b"85010112345")
    s = Sealer(b"e" * 32)
    tr = StateTracker(fs, (out, "/srv/out"), sealer=s, sealed_info=INFO)
    t = tr.target(full=True)
    assert "/tmp/scratch" not in t and "/tmp" not in t
    el = t["/srv/out/result.json"]
    assert b"result.json" not in el and is_sealed(c.decode(el)[1])
    assert s.open_fields(c.decode(el))[1] == "/srv/out/result.json"
    doc = json.loads(tr.last_config)
    assert doc["sealed"] == {**INFO, "rootfs_ro": True, "log_driver": "none", "tmpfs": ["/tmp"]}
    assert tr.update(full=True) and tr.update(full=True) == []     # deterministic: no churn between scans


def test_unsealed_tracker_unchanged(tmp_path):
    tr = StateTracker(FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS), (tmp_path, "/srv/out"))
    tr.target()
    assert "sealed" not in json.loads(tr.last_config)


def _sealed_violations(doc, policy):
    return [v for v in config_violations(doc, policy) if v.startswith("sealed")]


def test_require_sealed():
    fs = FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS)
    doc = config_doc(fs.inspect(), fs.network_internal)
    plain = parse(POLICY)
    strict = parse(POLICY + b"require_sealed: true\n")
    assert not plain.require_sealed and strict.require_sealed
    assert config_violations(doc, plain) == []
    assert _sealed_violations(doc, strict) == ["sealed mode required but the run is not sealed"]
    good = {**INFO, "rootfs_ro": True, "log_driver": "none", "tmpfs": ["/tmp"]}
    assert _sealed_violations({**doc, "sealed": good}, strict) == []
    for bad in ({"rootfs_ro": False}, {"log_driver": "json-file"}, {"swap": True}):
        assert len(_sealed_violations({**doc, "sealed": {**good, **bad}}, strict)) == 1
