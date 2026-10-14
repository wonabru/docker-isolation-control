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
