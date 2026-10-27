import json

import pytest

from poi.seal import SealError, b64d, b64e
from poi.seal.grant import (FP_LABEL, RunKey, bundle_label, make_grant, open_grant, read_run_pub,
                            wait_for_grant)


def test_roundtrip():
    rk = RunKey.generate("r1")
    assert read_run_pub(rk.pub_bytes()) == ("r1", rk.pk)
    keys = {bundle_label("d" * 64): b"k" * 32, FP_LABEL: b"f" * 32}
    assert open_grant(make_grant(rk.pub_bytes(), keys), rk) == keys


def test_other_run_rejected():
    g = make_grant(RunKey.generate("r1").pub_bytes(), {"bundle:x": b"k" * 32})
    with pytest.raises(SealError):
        open_grant(g, RunKey.generate("r2"))
    with pytest.raises(SealError):                  # same id, different (fresh) run key
        open_grant(g, RunKey.generate("r1"))


def test_relabelled_key_rejected():
    rk = RunKey.generate("r1")
    d = json.loads(make_grant(rk.pub_bytes(), {"bundle:a": b"k" * 32}))
    d["keys"] = {"bundle:b": d["keys"]["bundle:a"]}
    with pytest.raises(SealError):
        open_grant(json.dumps(d).encode(), rk)


def test_garbage_rejected():
    with pytest.raises(SealError):
        open_grant(b"not json", RunKey.generate("r1"))
    with pytest.raises(SealError):
        open_grant(json.dumps({"v": 1, "run_id": "r1", "keys": {"a": b64e(b"x")}}).encode(),
                   RunKey.generate("r1"))
    assert b64d(b64e(b"x")) == b"x"


def _clock():
    t = [0.0]

    def sleep(s):
        t[0] += s
    return t, sleep, (lambda: t[0])


def test_wait_skips_bad_grant_then_accepts(tmp_path):
    rk = RunKey.generate("r1")
    path = tmp_path / "grant.bin"
    path.write_bytes(make_grant(RunKey.generate("r1").pub_bytes(), {"bundle:x": b"k" * 32}))
    t, base_sleep, mono = _clock()

    def sleep(s):
        base_sleep(s)
        if t[0] >= 1:
            path.write_bytes(make_grant(rk.pub_bytes(), {"bundle:x": b"k" * 32}))
    assert wait_for_grant(path, rk, {"bundle:x"}, 10, sleep=sleep, monotonic=mono) == {"bundle:x": b"k" * 32}


def test_wait_times_out_without_grant_or_with_missing_key(tmp_path):
    rk = RunKey.generate("r1")
    _, sleep, mono = _clock()
    with pytest.raises(SealError, match="no valid grant"):
        wait_for_grant(tmp_path / "grant.bin", rk, {"bundle:x"}, 3, sleep=sleep, monotonic=mono)
    (tmp_path / "grant.bin").write_bytes(make_grant(rk.pub_bytes(), {"bundle:x": b"k" * 32}))
    _, sleep, mono = _clock()
    with pytest.raises(SealError):
        wait_for_grant(tmp_path / "grant.bin", rk, {"bundle:x", FP_LABEL}, 3, sleep=sleep, monotonic=mono)
