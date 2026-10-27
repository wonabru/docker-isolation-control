import pytest

from poi.seal import SealError, kem


def test_sizes_and_roundtrip():
    sk, pk = kem.generate()
    assert (len(sk), len(pk)) == (kem.SK_LEN, kem.PK_LEN) == (96, 1216)
    assert kem.public_from_private(sk) == pk
    ct, ss = kem.encaps(pk)
    assert len(ct) == kem.CT_LEN == 1120 and kem.decaps(sk, ct) == ss
    blob = kem.wrap(pk, b"k" * 32, b"ctx")
    assert kem.unwrap(sk, blob, b"ctx") == b"k" * 32


@pytest.mark.parametrize("pos", [0, kem.CT_M - 1, kem.CT_M, kem.CT_LEN - 1, kem.CT_LEN])
def test_tampering_rejected(pos):          # ML-KEM part, X25519 part, AEAD part
    sk, pk = kem.generate()
    blob = bytearray(kem.wrap(pk, b"k" * 32, b"ctx"))
    blob[pos] ^= 1
    with pytest.raises(SealError):
        kem.unwrap(sk, bytes(blob), b"ctx")


def test_wrong_context_or_key_rejected():
    sk, pk = kem.generate()
    other, _ = kem.generate()
    blob = kem.wrap(pk, b"k" * 32, b"ctx")
    with pytest.raises(SealError):
        kem.unwrap(sk, blob, b"other")
    with pytest.raises(SealError):
        kem.unwrap(other, blob, b"ctx")
    with pytest.raises(SealError):
        kem.unwrap(sk, blob[:100], b"ctx")
