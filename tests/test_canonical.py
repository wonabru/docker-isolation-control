import pytest

from poi import canonical as c


def test_canonical_json_is_deterministic():
    assert c.canonical_json({"b": 1, "a": [1, {"d": 2, "c": 3}]}) == b'{"a":[1,{"c":3,"d":2}],"b":1}'


def test_domain_separation():
    assert c.encode("file", "x") != c.encode("egress", "x")
    assert c.file_element("/a", "file", 0o644, 0, 0, "aa") != c.egress_element(
        0, "/a", "file", "644", "0", "0", "aa", "allow", "")


def test_file_element_layout():
    assert c.file_element("/etc/x", "file", 0o100644, 0, 0, "ab") == b"\x00".join(
        [b"file", b"/etc/x", b"file", b"644", b"0", b"0", b"ab"])


def test_nul_rejected():
    with pytest.raises(ValueError):
        c.encode("file", "a\0b")


def test_decode_roundtrip():
    e = c.egress_element(7, "2026-01-01T00:00:00Z", "POST", "api.x", "/v1", "h", "b", "block", "schema")
    assert c.decode(e) == ["egress", "7", "2026-01-01T00:00:00Z", "POST", "api.x", "/v1", "h", "b", "block", "schema"]


def test_headers_digest_order_and_case_insensitive():
    assert c.headers_digest([("A", "1"), ("b", "2")]) == c.headers_digest([("B", "2"), ("a", "1")])


def test_checkpoint_digest_ignores_sig():
    cp = {"seq": 1, "x": "y", "sig": "aa"}
    assert c.checkpoint_digest(cp) == c.checkpoint_digest({**cp, "sig": "bb"})
