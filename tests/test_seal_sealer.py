import json

import pytest

from poi import canonical as c
from poi.seal import SealError, kem
from poi.seal.sealer import (EV_MAGIC, LOCKED, Sealer, display_fields, is_sealed, open_sealed_doc,
                             sealed_doc)

T = "2026-10-27T10:00:00Z"
S = Sealer(b"e" * 32)


def test_evidence_deterministic_roundtrip():
    a = S.seal_evidence(b"pesel 85010112345")
    assert a == S.seal_evidence(b"pesel 85010112345") and a.startswith(EV_MAGIC) and b"85010112345" not in a
    assert S.open_evidence(a) == b"pesel 85010112345"
    assert S.open_evidence(S.seal_evidence(b"")) == b""
    assert S.open_evidence(b'{"plain":"config"}') == b'{"plain":"config"}'
    with pytest.raises(SealError):
        Sealer(b"x" * 32).open_evidence(a)


def test_egress_element_sealed_in_place():
    el = c.egress_element(1, T, "POST", "evil.test", "/c/85010112345", "h" * 64, "b" * 64, "block", "host-not-allowed")
    sealed = S.seal_element(el)
    f = c.decode(sealed)
    assert len(f) == len(c.decode(el)) and is_sealed(f[4]) and is_sealed(f[5])
    assert (f[3], f[6], f[7], f[8], f[9]) == ("POST", "h" * 64, "b" * 64, "block", "host-not-allowed")
    assert b"85010112345" not in sealed and b"evil" not in sealed
    assert S.seal_element(el) == sealed
    assert S.open_fields(f) == c.decode(el)


def test_dns_file_and_untouched_domains():
    dns = c.dns_element(2, T, "85010112345.evil.test", "A", "block")
    assert is_sealed(c.decode(S.seal_element(dns))[3])
    fe = c.file_element("/srv/out/r.json", "file", 0o644, 0, 0, "d" * 64)
    f = c.decode(S.seal_element(fe))
    assert is_sealed(f[1]) and is_sealed(f[6]) and f[2] == "file"
    assert S.open_fields(f) == c.decode(fe)
    for el in (c.ingress_element(1, 200, "h" * 64, "b" * 64), c.config_element("c" * 64)):
        assert S.seal_element(el) == el


def test_field_name_is_bound():
    v = S.seal_field("egress.host", "evil.test")
    with pytest.raises(SealError):
        S.open_field("egress.path", v)
    assert S.open_field("egress.path", "/plain") == "/plain"


def test_display_fields():
    f = c.decode(S.seal_element(c.dns_element(2, T, "x.evil.test", "A", "block")))
    assert display_fields(f)[3] == LOCKED and display_fields(f)[5] == "block"


def test_sealed_doc():
    sk, pk = kem.generate()
    raw = sealed_doc(b"e" * 32, pk, "r1", b"run-pub")
    d = json.loads(raw)
    assert (d["run_id"], d["client_pub"], d["run_pub"]) == ("r1", c.b2b256(pk), c.b2b256(b"run-pub"))
    assert open_sealed_doc(raw, sk).open_evidence(S.seal_evidence(b"x")) == b"x"
    other, _ = kem.generate()
    with pytest.raises(SealError):
        open_sealed_doc(raw, other)
    with pytest.raises(SealError):
        open_sealed_doc(b"{}", sk)
