import threading

from poi import canonical as c
from poi import evidence
from poi.wal import WalReader, WalWriter

T = "2026-10-13T18:00:00Z"


def _w(tmp_path):
    return WalWriter(tmp_path / "wal", tmp_path / "evidence")


def test_shared_seq_and_reader(tmp_path):
    w = _w(tmp_path)
    s1 = w.record_egress(T, "POST", "api.x", "/v1", [("A", "1")], b"{}", "allow", "")
    s2 = w.record_dns(T, "evil.com.", "A", "block")
    w.record_ingress(s1, 200, [], b"ok")
    assert (s1, s2) == (1, 2)
    entries = WalReader(tmp_path / "wal").read_new()
    assert [(e.kind, e.seq) for e in entries] == [("egress", 1), ("dns", 2), ("ingress", 1)]
    f = c.decode(entries[0].element)
    assert evidence.get(tmp_path / "evidence", f[7]) == b"{}"
    assert f[6] == c.headers_digest([("a", "1")])


def test_reader_is_incremental_and_skips_partial_line(tmp_path):
    w = _w(tmp_path)
    r = WalReader(tmp_path / "wal")
    w.record_dns(T, "a.", "A", "block")
    assert len(r.read_new()) == 1
    with open(w.path, "ab") as f:
        f.write(b'{"kind":"dns"')
    assert r.read_new() == []


def test_writer_recovers_seq_and_truncates_torn_write(tmp_path):
    w = _w(tmp_path)
    w.record_dns(T, "a.", "A", "block")
    w.record_dns(T, "b.", "A", "block")
    with open(w.path, "ab") as f:
        f.write(b'{"kind":"dn')
    w2 = _w(tmp_path)
    assert w2.seq == 2
    assert w2.record_dns(T, "c.", "A", "block") == 3
    assert [e.seq for e in WalReader(tmp_path / "wal").read_new()] == [1, 2, 3]


def test_concurrent_writers_unique_seqs(tmp_path):
    w = _w(tmp_path)
    ts = [threading.Thread(target=lambda: [w.record_dns(T, "x.", "A", "block") for _ in range(50)])
          for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(e.seq for e in WalReader(tmp_path / "wal").read_new()) == list(range(1, 201))


def test_sealed_writer_keeps_client_data_out_of_files(tmp_path):
    from poi.seal.sealer import Sealer
    s = Sealer(b"e" * 32)
    w = WalWriter(tmp_path / "wal", tmp_path / "evidence", sealer=s)
    seq = w.record_egress(T, "POST", "evil.test", "/c/85010112345", [("x-covert", "85010112345")],
                          b'{"pesel":"85010112345"}', "block", "host-not-allowed")
    w.record_dns(T, "85010112345.evil.test", "A", "block")
    w.record_ingress(seq, 200, [], b"85010112345")
    for p in [w.path, *(tmp_path / "evidence").iterdir()]:
        assert b"85010112345" not in p.read_bytes()
    entries = WalReader(tmp_path / "wal").read_new()
    assert all(b"85010112345" not in e.element for e in entries)
    f = s.open_fields(c.decode(entries[0].element))
    assert (f[4], f[5]) == ("evil.test", "/c/85010112345")
    assert s.open_evidence(evidence.get(tmp_path / "evidence", f[7])) == b'{"pesel":"85010112345"}'
    assert s.open_fields(c.decode(entries[1].element))[3] == "85010112345.evil.test"
