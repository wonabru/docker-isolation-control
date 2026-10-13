from poi import evidence
from poi.canonical import b2b256


def test_put_get_roundtrip(tmp_path):
    d = evidence.put(tmp_path, b"body")
    assert d == b2b256(b"body")
    assert evidence.get(tmp_path, d) == b"body"
    assert evidence.put(tmp_path, b"body") == d          # idempotent


def test_missing_and_corrupt_return_none(tmp_path):
    assert evidence.get(tmp_path, "0" * 64) is None
    d = evidence.put(tmp_path, b"body")
    (tmp_path / f"{d}.bin").write_bytes(b"tampered")
    assert evidence.get(tmp_path, d) is None
