import os

import pytest

from poi.lthash import LtHash
from poi.state import StateTracker, config_doc, mount_content_digest

from helpers import FakeFS

IMAGE = {"/etc": None, "/etc/os": b"ubuntu", "/opt": None, "/opt/lib.so": b"ELF", "/hf": None}


def _model_dir(tmp_path):
    d = tmp_path / "model"
    (d / "blobs").mkdir(parents=True)
    (d / "snapshots" / "abc").mkdir(parents=True)
    (d / "blobs" / "w1").write_bytes(b"weights-1")
    os.symlink("../../blobs/w1", d / "snapshots" / "abc" / "model.safetensors")
    return d


def test_mount_content_digest_tracks_files_and_symlinks(tmp_path):
    d = _model_dir(tmp_path)
    cache = {}
    first = mount_content_digest(d, cache)
    assert first == mount_content_digest(d, cache) and len(cache) == 1
    (d / "blobs" / "w1").write_bytes(b"weights-2")          # same size, different weights
    os.utime(d / "blobs" / "w1", ns=(1, 2_000_000_000))      # a new mtime, as any real rewrite gets
    assert mount_content_digest(d, cache) != first
    assert mount_content_digest(d) == mount_content_digest(d, cache)    # cache never changes the answer
    os.remove(d / "snapshots" / "abc" / "model.safetensors")
    os.symlink("../../blobs/other", d / "snapshots" / "abc" / "model.safetensors")
    assert mount_content_digest(d) != first


def test_config_doc_gpus_shm_and_mount_content():
    fs = FakeFS(IMAGE, mounts=[{"Destination": "/hf", "RW": False, "Type": "bind", "Source": "/x"}])
    fs.host_extra = {"DeviceRequests": [{"Driver": "", "Count": -1, "Capabilities": [["gpu"]]}],
                     "ShmSize": 1 << 30}
    doc = config_doc(fs.inspect(), fs.network_internal, {"/hf": "d" * 64})
    assert doc["gpus"] == [{"count": -1, "capabilities": ["gpu"], "driver": ""}]
    assert doc["shm_size"] == 1 << 30
    assert doc["mounts"] == [{"destination": "/hf", "rw": False, "type": "bind", "content": "d" * 64}]
    plain = config_doc(FakeFS(IMAGE).inspect(), fs.network_internal)
    assert plain["gpus"] == [] and plain["shm_size"] == 0


def test_config_doc_attests_nvidia_runtime_gpus():
    """GPUs attached by the nvidia runtime are attested too (policy allow_gpu checks them)."""
    fs = FakeFS(IMAGE)
    fs.host_extra = {"Runtime": "nvidia"}
    insp = fs.inspect()
    insp["Config"]["Env"] = ["PATH=/bin", "NVIDIA_VISIBLE_DEVICES=0,1,2,3"]
    assert config_doc(insp, fs.network_internal)["gpus"] == [{"runtime": "nvidia", "visible_devices": "0,1,2,3"}]
    insp["Config"]["Env"] = ["NVIDIA_VISIBLE_DEVICES=void"]
    assert config_doc(insp, fs.network_internal)["gpus"] == []
    insp["HostConfig"]["Runtime"] = "runc"
    insp["Config"]["Env"] = ["NVIDIA_VISIBLE_DEVICES=all"]                # env alone attaches nothing under runc
    assert config_doc(insp, fs.network_internal)["gpus"] == []


def _apply(h, ops):
    for op in ops:
        (h.add if op.op == "add" else h.sub)(op.element)
    return h


class NoExportFS(FakeFS):
    def export(self):
        raise AssertionError("digest mode must not export the filesystem")

    def export_image(self):
        raise AssertionError("digest mode must not export the image")


def test_digest_mode_tracks_only_the_diff():
    fs = NoExportFS(IMAGE)
    tr = StateTracker(fs, image_mode="digest")
    tr.load_image()
    h = _apply(LtHash(), tr.update())
    assert list(tr.index) == ["\0config"]                     # image files are not enumerated
    fs.write("/tmp", None)
    fs.write("/tmp/cache.bin", b"x")
    fs.write("/etc/os", b"changed")
    fs.delete("/opt")
    h = _apply(h, tr.update())
    assert set(tr.index) == {"\0config", "/tmp", "/tmp/cache.bin", "/etc/os", "/opt", "/opt/lib.so"}
    assert tr.index["/opt"].split(b"\0")[2] == b"deleted"
    full = StateTracker(fs, image_mode="digest")
    assert h == LtHash.of(full.target(full=True).values())   # live check agrees without exporting
    fs.delete("/tmp/cache.bin")
    h = _apply(h, tr.update(full=True))
    assert "/tmp/cache.bin" not in tr.index and h == LtHash.of(tr.index.values())


def test_attested_mount_change_changes_config(tmp_path):
    d = _model_dir(tmp_path)
    fs = FakeFS(IMAGE, mounts=[{"Destination": "/hf", "RW": False, "Type": "bind", "Source": str(d)}])
    tr = StateTracker(fs, image_mode="digest", attest_mounts=("/hf",))
    tr.load_image()
    tr.update()
    assert b'"content":' in tr.last_config
    assert tr.update() == []
    (d / "blobs" / "w1").write_bytes(b"swapped model")
    ops = tr.update(full=True)                                  # changed files are re-hashed
    assert [o.op for o in ops] == ["sub", "add"] and ops[1].element.startswith(b"config\0")


def test_full_scan_does_not_reread_unchanged_mount(tmp_path, monkeypatch):
    import poi.state as state
    d = _model_dir(tmp_path)
    fs = FakeFS(IMAGE, mounts=[{"Destination": "/hf", "RW": False, "Type": "bind", "Source": str(d)}])
    tr = StateTracker(fs, image_mode="digest", attest_mounts=("/hf",))
    tr.load_image()
    reads = []
    real = state._digest_stream
    monkeypatch.setattr(state, "_digest_stream", lambda f: reads.append(f.name) or real(f))
    tr.update(full=True)
    first = len(reads)
    assert first > 0
    assert tr.update(full=True) == [] and len(reads) == first   # weights hashed once, not every full scan
    (d / "blobs" / "w1").write_bytes(b"swapped model")
    ops = tr.update()                                           # any tick catches a changed file
    assert [o.op for o in ops] == ["sub", "add"] and len(reads) == first + 1


def test_unknown_image_mode_rejected():
    with pytest.raises(ValueError):
        StateTracker(FakeFS(IMAGE), image_mode="layers")
