"""`poi dashboard`: local web UI over a verified Mirror. Binds to 127.0.0.1, session key required."""
from __future__ import annotations

import hmac
import json
import math
import re
import secrets
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlsplit

from poi import canonical as c
from poi.mirror import Mirror
from poi.policy import endpoint_capacity
from poi.verify import parse_delta

PREVIEW = 64 * 1024
TIMELINE = 200
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8")}
CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'"
_NUM = re.compile(r"^\d{1,9}$")


def preview(data: bytes | None) -> dict | None:
    if data is None:
        return None
    cut = data[:PREVIEW]
    try:
        return {"text": cut.decode("utf-8"), "size": len(data), "truncated": len(data) > PREVIEW}
    except UnicodeDecodeError:
        return {"hex": cut.hex(), "size": len(data), "truncated": len(data) > PREVIEW}


class DashboardApp:
    def __init__(self, mirror: Mirror, source_label: str = "") -> None:
        self.m = mirror
        self.source_label = source_label
        self._cp_cache: dict[int, dict] = {}
        self._sizes: dict[str, int | None] = {}

    # -- helpers --------------------------------------------------------------------
    def _evidence(self, digest: str) -> bytes | None:
        return self.m.evidence(digest)

    def _size(self, digest) -> int | None:
        """Bytes of one evidence blob (cached); None when it is sealed or missing."""
        if not isinstance(digest, str) or not digest:
            return None
        if digest not in self._sizes:
            data = self._evidence(digest)
            self._sizes[digest] = None if data is None else len(data)
        return self._sizes[digest]

    def _ingress(self) -> dict:
        return {e.seq: e for e in self.m.verifier.res.ingress}

    def _event_row(self, ev, ingress: dict | None = None) -> dict:
        f = self.m.fields(ev.fields)
        hit = self.m.hits.get(ev.seq)
        if ev.domain == "dns":
            row = {"seq": ev.seq, "kind": "dns", "t": f[2], "target": f[3], "qtype": f[4],
                   "verdict": f[5], "reason": "" if f[5] == "allow" else "dns"}
        else:
            row = {"seq": ev.seq, "kind": "http", "t": f[2], "method": f[3], "host": f[4], "path": f[5],
                   "target": f"{f[3]} {f[4]}{f[5]}", "verdict": f[8], "reason": f[9], "out_bytes": self._size(f[7])}
            ing = (ingress if ingress is not None else self._ingress()).get(ev.seq)
            if ing is not None:
                g = self.m.fields(ing.fields)
                row.update(in_status=int(g[2]) if str(g[2]).isdigit() else None, in_bytes=self._size(g[4]))
        row.update(checkpoint=ev.checkpoint, hit=hit[1] if hit else None, acked=ev.seq in self.m.acks)
        return row

    def _cp_stats(self, seq: int) -> dict:
        if seq in self._cp_cache:
            return self._cp_cache[seq]
        cp = self.m.verifier.res.checkpoints[seq]
        raw = (self.m.dir / "delta" / f"{seq:06d}.jsonl").read_bytes()
        files = {"added": [], "removed": [], "changed": []}
        subs, adds, config = {}, {}, None
        egress = blocked = 0
        for op, acc, element in parse_delta(cp, raw):
            f = c.decode(element)
            if f[0] == "file":
                (adds if op == "add" else subs)[f[1]] = self.m.fields(f)[1]
            elif f[0] == "config" and op == "add":
                config = f[1]
            elif f[0] in ("egress", "dns"):
                egress += 1
                blocked += (f[8] if f[0] == "egress" else f[5]) != "allow"
        for p in sorted(adds.keys() | subs.keys()):
            key = "changed" if p in adds and p in subs else ("added" if p in adds else "removed")
            files[key].append(adds.get(p) or subs.get(p))
        stats = {"seq": seq, "t": cp["t"], "files": files, "config": config, "egress": egress,
                 "blocked": blocked, "restart": cp.get("restart", False)}
        self._cp_cache[seq] = stats
        return stats

    # -- API --------------------------------------------------------------------------
    def summary(self) -> dict:
        m = self.m
        with m.lock:
            res = m.verifier.res
            verdict = m.verdict()
            allowed = Counter()
            blocked = dns = 0
            for ev in res.egress:
                f = m.fields(ev.fields)
                if ev.domain == "dns":
                    dns += 1
                    blocked += f[5] != "allow"
                elif f[8] == "allow":
                    allowed[(f[4], f[3], f[5])] += 1
                else:
                    blocked += 1
            cap = 0.0
            for (host, method, path), n in allowed.items():
                ep = m.policy.find(host, method, path)
                cap += (endpoint_capacity(ep) if ep else math.inf) * n
            last = res.checkpoints[-1] if res.checkpoints else None
            n = len(res.checkpoints)
            hit_cps = {ev.checkpoint for ev in res.egress if ev.seq in m.hits}
            # Data volume both ways: request bodies that left (sent) and response bodies that came back.
            out_bytes = sum(self._size(m.fields(ev.fields)[7]) or 0 for ev in res.egress
                            if ev.domain == "egress" and m.fields(ev.fields)[8] == "allow")
            in_bytes = sum(self._size(m.fields(ev.fields)[4]) or 0 for ev in res.ingress)
            timeline = []
            for seq in range(max(0, n - TIMELINE), n):
                s = self._cp_stats(seq)
                timeline.append({"seq": seq, "t": s["t"], "changes": sum(map(len, s["files"].values())),
                                 "egress": s["egress"], "blocked": s["blocked"], "hit": seq in hit_cps,
                                 "config": s["config"] is not None and seq > 0})
            if m.error is not None and m.error.seq is not None and m.error.seq >= n:
                timeline.append({"seq": m.error.seq, "failed": True})
            age = None if m.last_received is None else round(m.monotonic() - m.last_received, 1)
            return {
                "version": m.version,
                "source": self.source_label,
                "verdict": {"level": verdict.level, "reasons": verdict.reasons},
                "finished": res.finished,
                "last_checkpoint": None if last is None else {"seq": last["seq"], "t": last["t"],
                                                                "state": last["state"]["digest"],
                                                                "age_s": age},
                "sent": sum(allowed.values()), "blocked": blocked, "dns": dns,
                "hits_allowed": sum(1 for v, _ in m.hits.values() if v == "allow"),
                "hits_blocked": sum(1 for v, _ in m.hits.values() if v != "allow"),
                "capacity_bits": None if math.isinf(cap) else round(cap, 1),
                "traffic": {"out_requests": sum(allowed.values()), "out_bytes": out_bytes,
                            "in_responses": len(res.ingress), "in_bytes": in_bytes},
                "timeline": timeline,
                "operator": m.runtime,
                "source_error": m.source_error,
                "tick_seconds": m.policy.tick_seconds,
            }

    def events(self, before: int | None, limit: int, kind: str) -> list[dict]:
        with self.m.lock:
            evs = self.m.verifier.res.egress
            ingress = self._ingress()
            out = []
            for ev in reversed(evs):
                if before is not None and ev.seq >= before:
                    continue
                row = self._event_row(ev, ingress)
                if kind == "allowed" and row["verdict"] != "allow":
                    continue
                if kind == "blocked" and row["verdict"] == "allow":
                    continue
                if kind == "dns" and row["kind"] != "dns":
                    continue
                out.append(row)
                if len(out) >= limit:
                    break
            return out

    def event(self, seq: int) -> dict | None:
        with self.m.lock:
            res = self.m.verifier.res
            ev = next((e for e in res.egress if e.seq == seq), None)
            if ev is None:
                return None
            row = self._event_row(ev)
            cp = res.checkpoints[ev.checkpoint]
            row["proof"] = {"checkpoint": ev.checkpoint, "checkpoint_t": cp["t"],
                            "egress_accumulator": cp["egress"]["digest"], "signature": "verified",
                            "element": c.encode(*ev.fields).decode("utf-8").replace("\0", " │ ")}
            if ev.domain == "egress":
                f = self.m.fields(ev.fields)
                hdr = self._evidence(f[6])
                body = self._evidence(f[7])
                row["headers"] = json.loads(hdr) if hdr else None
                row["body"] = preview(body)
                if body is not None and f[3] != "CONNECT":
                    d = self.m.policy.decide(f[4], f[3], f[5], body)
                    row["policy_recheck"] = {"verdict": d.verdict, "reason": d.reason}
                ing = next((e for e in res.ingress if e.seq == seq), None)
                if ing is not None:
                    ih = self._evidence(ing.fields[3])
                    row["response"] = {"status": int(ing.fields[2]),
                                       "headers": json.loads(ih) if ih else None,
                                       "body": preview(self._evidence(ing.fields[4]))}
            return row

    def checkpoint(self, seq: int) -> dict | None:
        with self.m.lock:
            res = self.m.verifier.res
            if not 0 <= seq < len(res.checkpoints):
                return None
            cp = res.checkpoints[seq]
            s = self._cp_stats(seq)
            prev_cfg = None
            for prev in range(seq - 1, -1, -1):
                if (pc := self._cp_stats(prev)["config"]) is not None:
                    prev_cfg = pc
                    break
            config = None
            if s["config"] is not None:
                after = self._evidence(s["config"])
                before = self._evidence(prev_cfg) if prev_cfg else None
                config = {"before": json.loads(before) if before else None,
                          "after": json.loads(after) if after else None}
            return {"seq": seq, "t": cp["t"], "prev": cp["prev"], "delta": cp["delta"], "policy": cp["policy"],
                    "state": cp["state"]["digest"], "egress": cp["egress"]["digest"],
                    "ingress": cp["ingress"]["digest"], "egress_count": cp["egress"]["count"],
                    "ingress_count": cp["ingress"]["count"], "restart": cp.get("restart", False),
                    "rotate": cp.get("rotate"), "signature": "verified", "files": s["files"],
                    "config_change": config,
                    "events": [e.seq for e in res.egress if e.checkpoint == seq]}


def make_dashboard_server(app: DashboardApp, session_key: str, host: str = "127.0.0.1",
                          port: int = 8780) -> ThreadingHTTPServer:
    static_dir = resources.files("poi") / "dashboard_static"
    cookie = f"poi_session={session_key}"

    class Handler(BaseHTTPRequestHandler):
        server_version = "poi-dashboard"

        def log_message(self, *args) -> None:
            pass

        def _authed(self, url) -> bool:
            q = parse_qs(url.query).get("key", [""])[0]
            cookies = [x.strip() for x in (self.headers.get("cookie") or "").split(";")]
            return hmac.compare_digest(q, session_key) or any(hmac.compare_digest(x, cookie) for x in cookies)

        def _headers(self, code: int, ctype: str, length: int | None = None, extra=()) -> None:
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("content-security-policy", CSP)
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("cache-control", "no-store")
            for k, v in extra:
                self.send_header(k, v)
            if length is not None:
                self.send_header("content-length", str(length))
            self.end_headers()

        def _json(self, obj, code: int = 200) -> None:
            body = json.dumps(obj).encode()
            self._headers(code, "application/json", len(body))
            self.wfile.write(body)

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            if not self._authed(url):
                return self._json({"error": "missing or wrong session key"}, 403)
            if url.path in STATIC:
                name, ctype = STATIC[url.path]
                body = (static_dir / name).read_bytes()
                extra = [("set-cookie", f"{cookie}; HttpOnly; SameSite=Strict; Path=/")] if url.path == "/" else []
                self._headers(200, ctype, len(body), extra)
                return self.wfile.write(body)
            q = parse_qs(url.query)
            parts = url.path.strip("/").split("/")
            if url.path == "/api/summary":
                return self._json(app.summary())
            if url.path == "/api/events":
                before = q.get("before", [None])[0]
                kind = q.get("kind", ["all"])[0]
                try:
                    limit = min(int(q.get("limit", ["100"])[0]), 500)
                    before_i = int(before) if before else None
                except ValueError:
                    return self._json({"error": "bad query"}, 400)
                return self._json(app.events(before_i, limit, kind))
            if len(parts) == 3 and parts[:2] in (["api", "event"], ["api", "checkpoint"]) and _NUM.match(parts[2]):
                obj = (app.event if parts[1] == "event" else app.checkpoint)(int(parts[2]))
                return self._json(obj) if obj is not None else self._json({"error": "not found"}, 404)
            if url.path == "/api/stream":
                return self._stream()
            return self._json({"error": "not found"}, 404)

        def do_POST(self) -> None:
            url = urlsplit(self.path)
            if not self._authed(url) or self.headers.get("x-poi") != "1":
                return self._json({"error": "forbidden"}, 403)
            parts = url.path.strip("/").split("/")
            if len(parts) == 3 and parts[:2] == ["api", "ack"] and _NUM.match(parts[2]):
                ok = app.m.ack(int(parts[2]))
                return self._json({"ok": ok}, 200 if ok else 404)
            return self._json({"error": "not found"}, 404)

        def _stream(self) -> None:
            self._headers(200, "text/event-stream")
            m = app.m
            seen = -1
            try:
                while True:
                    with m.lock:
                        if m.version == seen:
                            m.changed.wait(timeout=2.0)       # heartbeat keeps ages and staleness fresh
                        seen = m.version
                    data = json.dumps(app.summary())
                    self.wfile.write(f"event: update\ndata: {data}\n\n".encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv


def new_session_key() -> str:
    return secrets.token_urlsafe(24)


def serve_in_background(srv: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t
