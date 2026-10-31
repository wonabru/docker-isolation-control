import json
import urllib.request

import pytest

from poi.dashboard import preview

from helpers import DASH_KEY as KEY, http_call as call, start_dashboard


@pytest.fixture
def dash(tmp_path, key):
    app, base, srv = start_dashboard(tmp_path, key)
    yield app, base
    srv.shutdown()


def test_api_requires_session_key(dash):
    _, base = dash
    assert call(base + "/api/summary")[0] == 403
    assert call(base + f"/api/summary?key={KEY}")[0] == 200
    assert call(base + "/api/summary", headers={"cookie": f"poi_session={KEY}"})[0] == 200
    assert call(base + "/api/summary", headers={"cookie": "poi_session=wrong"})[0] == 403


def test_summary(dash):
    app, _ = dash
    s = app.summary()
    assert s["verdict"]["level"] == "attention"
    assert (s["sent"], s["blocked"], s["dns"]) == (1, 2, 1)
    assert (s["hits_allowed"], s["hits_blocked"]) == (0, 1)
    assert s["capacity_bits"] == 9.0
    assert [t["seq"] for t in s["timeline"]] == [0, 1] and s["timeline"][1]["hit"] is True
    assert s["operator"] == {"status": "running"}


def test_events_and_filters(dash):
    app, _ = dash
    assert [e["seq"] for e in app.events(None, 100, "all")] == [3, 2, 1]
    assert [e["seq"] for e in app.events(None, 100, "allowed")] == [1]
    assert [e["seq"] for e in app.events(None, 100, "blocked")] == [3, 2]
    assert [e["seq"] for e in app.events(None, 100, "dns")] == [3]
    assert [e["seq"] for e in app.events(3, 1, "all")] == [2]


def test_event_detail(dash):
    app, _ = dash
    sent = app.event(1)
    assert sent["body"]["text"] == '{"count":1,"model":"small"}'
    assert sent["policy_recheck"] == {"verdict": "allow", "reason": ""}
    assert sent["response"]["status"] == 200 and sent["response"]["body"]["text"] == '{"score":0.5}'
    blocked = app.event(2)
    assert blocked["hit"] == ["patients.csv"] and blocked["body"]["text"].startswith("<script>")
    assert app.event(99) is None


def test_checkpoint_detail(dash):
    app, _ = dash
    c1 = app.checkpoint(1)
    assert c1["files"]["added"] == ["/tmp", "/tmp/x"] and c1["events"] == [1, 2, 3]
    c0 = app.checkpoint(0)
    assert c0["config_change"]["after"]["networks"] == [{"name": "poi-int", "internal": True}]
    assert app.checkpoint(5) is None


def test_ack_requires_custom_header(dash):
    app, base = dash
    cookie = {"cookie": f"poi_session={KEY}"}
    assert call(base + "/api/ack/2", "POST", cookie)[0] == 403
    assert call(base + "/api/ack/2", "POST", {**cookie, "x-poi": "1"})[0] == 200
    assert app.summary()["verdict"]["level"] == "verified"


def test_stream_sends_summary(dash):
    _, base = dash
    req = urllib.request.Request(base + "/api/stream", headers={"cookie": f"poi_session={KEY}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.readline() == b"event: update\n"
        data = json.loads(r.readline().split(b"data: ", 1)[1])
    assert data["verdict"]["level"] == "attention"


def test_preview_text_hex_truncation():
    assert preview(b"abc") == {"text": "abc", "size": 3, "truncated": False}
    assert preview(b"\xff\x00") == {"hex": "ff00", "size": 2, "truncated": False}
    assert preview(b"a" * 70000)["truncated"] is True


def test_traffic_both_directions(dash):
    app, _ = dash
    tr = app.summary()["traffic"]
    assert tr == {"out_requests": 1, "out_bytes": 27, "in_responses": 1, "in_bytes": 13}
    sent = next(e for e in app.events(None, 100, "all") if e["seq"] == 1)
    assert (sent["out_bytes"], sent["in_status"], sent["in_bytes"]) == (27, 200, 13)
