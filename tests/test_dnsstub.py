import socket

from dnslib import DNSRecord, RCODE

from poi import canonical as c
from poi.dnsstub import start_dns
from poi.wal import WalReader, WalWriter


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_dns_stub_logs_and_answers(tmp_path):
    wal = WalWriter(tmp_path / "wal", tmp_path / "ev")
    port = _free_port()
    srv = start_dns(wal, {"api.example.com"}, "10.0.0.5", address="127.0.0.1", port=port)
    try:
        ok = DNSRecord.parse(DNSRecord.question("api.example.com").send("127.0.0.1", port, timeout=2))
        bad = DNSRecord.parse(DNSRecord.question("c2VjcmV0.evil.com").send("127.0.0.1", port, timeout=2))
    finally:
        srv.stop()
    assert str(ok.rr[0].rdata) == "10.0.0.5"
    assert bad.header.rcode == RCODE.NXDOMAIN
    fields = [c.decode(e.element) for e in WalReader(tmp_path / "wal").read_new()]
    assert [(f[0], f[1], f[3], f[5]) for f in fields] == [
        ("dns", "1", "api.example.com", "allow"), ("dns", "2", "c2VjcmV0.evil.com", "block")]
