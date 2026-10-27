import os
import struct

import pytest

from poi.seal import SealError, bundle, kem


@pytest.fixture
def keys():
    return kem.generate()


def _tree(root):
    return {str(p.relative_to(root)): (p.read_bytes() if p.is_file() else None) for p in sorted(root.rglob("*"))}


def _src(tmp_path, size=5000):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "a.csv").write_bytes(os.urandom(size))
    (src / "sub" / "b.txt").write_bytes(b"hello patient 85010112345")
    return src


def _split(path):
    raw = path.read_bytes()
    n = struct.unpack(">I", raw[8:12])[0]
    return raw[:12 + n], raw[12 + n:]


def _unseal(path, sk, dest):
    bundle.unseal_to(path, bundle.dek_for(path, sk), dest)


def test_roundtrip_multi_chunk(tmp_path, keys):
    sk, pk = keys
    src = _src(tmp_path)
    p = tmp_path / "d.sealed"
    d = bundle.seal_dir(src, p, pk, chunk=1024)
    assert d == bundle.file_digest(p)
    raw = p.read_bytes()
    assert raw.startswith(bundle.MAGIC) and b"85010112345" not in raw
    assert len(_split(p)[1]) > 3 * (1024 + bundle.TAG)
    _unseal(p, sk, tmp_path / "out")
    assert _tree(tmp_path / "out") == _tree(src)


def test_empty_dir(tmp_path, keys):
    sk, pk = keys
    (tmp_path / "e").mkdir()
    bundle.seal_dir(tmp_path / "e", tmp_path / "e.sealed", pk)
    _unseal(tmp_path / "e.sealed", sk, tmp_path / "out")
    assert _tree(tmp_path / "out") == {}


def test_truncation_detected(tmp_path, keys):
    sk, pk = keys
    p = tmp_path / "d.sealed"
    bundle.seal_dir(_src(tmp_path), p, pk, chunk=1024)
    head, body = _split(p)
    step = 1024 + bundle.TAG
    p.write_bytes(head + body[: (len(body) - 1) // step * step])     # drop the final chunk
    with pytest.raises(SealError):
        _unseal(p, sk, tmp_path / "out")


def test_swapped_chunks_detected(tmp_path, keys):
    sk, pk = keys
    p = tmp_path / "d.sealed"
    bundle.seal_dir(_src(tmp_path), p, pk, chunk=1024)
    head, body = _split(p)
    step = 1024 + bundle.TAG
    p.write_bytes(head + body[step:2 * step] + body[:step] + body[2 * step:])
    with pytest.raises(SealError):
        _unseal(p, sk, tmp_path / "out")


def test_header_is_authenticated(tmp_path, keys):
    sk, pk = keys
    p = tmp_path / "d.sealed"
    bundle.seal_dir(_src(tmp_path), p, pk, chunk=1024)
    p.write_bytes(p.read_bytes().replace(b'"kind":"data"', b'"kind":"datx"', 1))
    with pytest.raises(SealError):
        _unseal(p, sk, tmp_path / "out")


def test_wrong_key_and_not_a_bundle(tmp_path, keys):
    _, pk = keys
    other, _ = kem.generate()
    p = tmp_path / "d.sealed"
    bundle.seal_dir(_src(tmp_path), p, pk)
    with pytest.raises(SealError):
        bundle.dek_for(p, other)
    (tmp_path / "x").write_bytes(b"hello")
    with pytest.raises(SealError):
        bundle.header_of(tmp_path / "x")
