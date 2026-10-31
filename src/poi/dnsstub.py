"""DNS stub for the internal network: logs every query as an egress event, answers only allow-listed hosts."""
from __future__ import annotations

from typing import Callable

from dnslib import QTYPE, RCODE, RR, A
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from poi.gate import utcnow
from poi.wal import WalWriter


class PoiResolver(BaseResolver):
    def __init__(self, wal: WalWriter, hosts: set[str], answer_ip: str,
                 clock: Callable[[], str] = utcnow, allow_all: bool = False,
                 isolated: Callable[[], bool] = lambda: False) -> None:
        self.wal, self.hosts, self.answer_ip, self.clock = wal, hosts, answer_ip, clock
        self.allow_all, self.isolated = allow_all, isolated

    def resolve(self, request, handler):
        qname = request.q.qname
        name = str(qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]
        allowed = not self.isolated() and (self.allow_all or name in self.hosts) and qtype == "A"
        reply = request.reply()
        try:
            self.wal.record_dns(self.clock(), name, qtype, "allow" if allowed else "block")
        except OSError:
            reply.header.rcode = RCODE.SERVFAIL
            return reply
        if allowed:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.answer_ip), ttl=60))
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


def start_dns(wal: WalWriter, hosts: set[str], answer_ip: str,
              address: str = "0.0.0.0", port: int = 53, allow_all: bool = False,
              isolated: Callable[[], bool] = lambda: False) -> DNSServer:
    server = DNSServer(PoiResolver(wal, hosts, answer_ip, allow_all=allow_all, isolated=isolated), address=address, port=port,
                       logger=DNSLogger(logf=lambda s: None))
    server.start_thread()
    return server
