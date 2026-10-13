from hypothesis import given, strategies as st

from poi.lthash import LtHash, N, VEC_BYTES, expand

elems = st.lists(st.binary(max_size=64), max_size=20)


def test_expand_shape_and_determinism():
    v = expand(b"hello")
    assert v.shape == (N,)
    assert (v == expand(b"hello")).all()
    assert not (v == expand(b"hellp")).all()


def test_empty_is_zero():
    assert LtHash().to_bytes() == bytes(VEC_BYTES)


@given(elems, elems)
def test_union_is_sum(a, b):
    assert LtHash.of(a + b) == LtHash.of(a) + LtHash.of(b)


@given(elems)
def test_order_independent(a):
    assert LtHash.of(a) == LtHash.of(list(reversed(a)))


@given(elems)
def test_sub_inverts_add(a):
    h = LtHash.of(a)
    for e in a:
        h.sub(e)
    assert h == LtHash()


@given(elems)
def test_roundtrip_b64(a):
    h = LtHash.of(a)
    assert LtHash.from_b64(h.to_b64()) == h


def test_golden_vectors():
    # Fixed vectors so independent implementations can cross-check.
    assert expand(b"").tobytes()[:8].hex() == GOLDEN_EXPAND_EMPTY_PREFIX
    assert LtHash.of([b"a", b"b"]).digest() == GOLDEN_DIGEST_AB
    assert LtHash().digest() == GOLDEN_DIGEST_EMPTY


GOLDEN_EXPAND_EMPTY_PREFIX = "96fb02154f98d8f1"
GOLDEN_DIGEST_AB = "62ad48880b6b900e906dea44e4d66b6d2fd2241aaf3da00f7fafda3588ee3fdc"
GOLDEN_DIGEST_EMPTY = "8d1d92b5b93941980d6780a1b566c67c5431d195ed33cccad74a60edd80513a4"
