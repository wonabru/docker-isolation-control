from poi.lthash import LtHash
from poi.state import CONFIG_KEY, StateTracker, config_doc, scan_tar

from helpers import FakeFS

IMAGE = {"/etc": None, "/etc/os": b"alpine", "/etc/motd": b"hi", "/bin": None,
         "/bin/sh": b"ELF", "/bin/ash": ("link", "/bin/sh"), "/srv": None}


def _apply(h: LtHash, ops):
    for op in ops:
        (h.add if op.op == "add" else h.sub)(op.element)
    return h


def _full_hash(fs, tr):
    return LtHash.of(tr.target(full=True).values())


def _genesis(fs, output=None):
    tr = StateTracker(fs, output)
    tr.load_image()
    h = _apply(LtHash(), tr.update())
    return tr, h


def test_genesis_equals_full_export():
    fs = FakeFS(IMAGE)
    tr, h = _genesis(fs)
    assert h == _full_hash(fs, StateTracker(fs))
    assert CONFIG_KEY in tr.index


def test_incremental_matches_full_scan_after_changes():
    fs = FakeFS(IMAGE)
    tr, h = _genesis(fs)
    fs.write("/etc/motd", b"changed")
    fs.write("/tmp", None)
    fs.write("/tmp/x", b"new")
    fs.delete("/bin")
    h = _apply(h, tr.update())
    assert h == _full_hash(fs, StateTracker(fs))
    fs.delete("/tmp/x")          # created then removed: disappears from diff
    h = _apply(h, tr.update())
    assert h == _full_hash(fs, StateTracker(fs))


def test_no_change_no_ops():
    fs = FakeFS(IMAGE)
    tr, _ = _genesis(fs)
    assert tr.update() == []


def test_mounts_excluded_and_output_volume_scanned(tmp_path):
    fs = FakeFS({**IMAGE, "/srv/out": None, "/srv/out/placeholder": b""},
                mounts=[{"Destination": "/srv/out", "RW": True, "Type": "bind"}])
    tr, h = _genesis(fs, (tmp_path, "/srv/out"))
    assert "/srv/out/placeholder" not in tr.index
    (tmp_path / "result.json").write_bytes(b"{}")
    ops = tr.update()
    assert [o.op for o in ops] == ["add"]
    assert "/srv/out/result.json" in tr.index


def test_config_change_produces_delta():
    fs = FakeFS(IMAGE)
    tr, _ = _genesis(fs)
    fs.networks["bridge"] = False
    ops = tr.update()
    assert [o.op for o in ops] == ["sub", "add"]
    assert ops[1].element.startswith(b"config\0")


def test_restore_index_then_full_update():
    fs = FakeFS(IMAGE)
    tr, h = _genesis(fs)
    fs.write("/etc/os", b"tampered")
    tr2 = StateTracker(fs)
    tr2.restore_index(tr.index.values())
    tr2.load_image()
    h = _apply(h, tr2.update(full=True))
    assert h == _full_hash(fs, StateTracker(fs))


def test_config_doc_shape():
    fs = FakeFS(IMAGE, mounts=[{"Destination": "/srv/out", "RW": True, "Type": "bind"}])
    d = config_doc(fs.inspect(), fs.network_internal)
    assert d["networks"] == [{"name": "poi-int", "internal": True}]
    assert d["mounts"] == [{"destination": "/srv/out", "rw": True, "type": "bind"}]


def test_scan_tar_symlink_and_dirs():
    idx = scan_tar(FakeFS(IMAGE).export())
    assert idx["/bin/ash"].split(b"\0")[2] == b"symlink"
    assert idx["/etc"].split(b"\0")[2] == b"dir"
