import base64
import gzip
import os
import urllib.parse

from poi.fingerprint import FingerprintSet, winnow

KEY = b"k" * 32
SECRET = b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma, address: ul. Lipowa 7, Krakow"


def fs():
    s = FingerprintSet(KEY)
    s.add(SECRET, "records/1.txt")
    return s


def test_winnow_deterministic_and_keyed():
    assert winnow(SECRET, KEY) == winnow(SECRET, KEY)
    assert winnow(SECRET, KEY) != winnow(SECRET, b"x" * 32)


def test_clean_traffic_no_hits():
    assert fs().scan(b'{"model":"small","count":3}') == set()
    assert fs().scan(os.urandom(4096)) == set()


def test_raw_substring_detected():
    assert fs().scan(b"prefix " + SECRET[5:80] + b" suffix") == {"records/1.txt"}


def test_whitespace_and_case_normalised():
    assert fs().scan(SECRET.upper().replace(b" ", b"\n")) == {"records/1.txt"}


def test_encoded_variants_detected():
    s = fs()
    assert s.scan(b'{"x":"' + base64.b64encode(SECRET) + b'"}')
    assert s.scan(SECRET.hex().encode())
    assert s.scan(urllib.parse.quote_from_bytes(SECRET).encode())
    assert s.scan(gzip.compress(SECRET))
    assert s.scan(base64.b64encode(gzip.compress(SECRET)))


def test_save_load(tmp_path):
    s = fs()
    s.save(tmp_path / "fp.bin")
    t = FingerprintSet.load(tmp_path / "fp.bin", KEY)
    assert t.prints == s.prints
    assert t.scan(SECRET) == {"?"}


def test_from_dir(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "r.txt").write_bytes(SECRET)
    assert FingerprintSet.from_dir(tmp_path, KEY).scan(SECRET) == {"a/r.txt"}
