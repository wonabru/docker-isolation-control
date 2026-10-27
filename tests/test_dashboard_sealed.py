import json

from poi.dashboard import DashboardApp
from poi.fingerprint import FingerprintSet
from poi.ledger import pubkey_hex
from poi.mirror import Mirror
from poi.source import LocalSource

from helpers import DASH_SECRET, make_sealed_run


def _app(tmp_path, key, run, sealer, name):
    fp = FingerprintSet(b"k" * 32)
    fp.add(DASH_SECRET, "patients.csv")
    m = Mirror(tmp_path / name, LocalSource(run, runtime=lambda: {"status": "exited"}), pubkey_hex(key), fp,
               sleep=lambda s: None, sealer=sealer)
    m.sync_once(wait=0)
    assert m.error is None
    return DashboardApp(m, "local")


def _blocked_http(app):
    return app.event(next(r["seq"] for r in app.events(None, 100, "blocked") if r["kind"] == "http"))


def test_without_client_key_everything_client_side_is_locked(tmp_path, key):
    run, _, _ = make_sealed_run(tmp_path, key)
    app = _app(tmp_path, key, run, None, "m1")
    assert (app.m.dir / "sealed.json").exists()
    row = _blocked_http(app)
    assert (row["host"], row["path"], row["body"], row["headers"]) == ("🔒", "🔒", None, None)
    assert app.m.hits == {}
    s = app.summary()
    assert s["blocked"] == 2 and s["capacity_bits"] is None
    assert app.checkpoint(1)["files"]["added"] == ["🔒"]
    dump = json.dumps([s, app.events(None, 100, "all"), app.checkpoint(1), row], ensure_ascii=False)
    assert "85010112345" not in dump and "evil.test" not in dump


def test_with_client_key_content_is_shown(tmp_path, key):
    run, sealer, _ = make_sealed_run(tmp_path, key)
    app = _app(tmp_path, key, run, sealer, "m2")
    row = _blocked_http(app)
    assert (row["host"], row["path"]) == ("evil.test", "/c/85010112345")
    assert "85010112345" in row["body"]["text"] and row["seq"] in app.m.hits
    assert app.summary()["capacity_bits"] is not None
    assert app.checkpoint(1)["files"]["added"] == ["/srv/out/r.txt"]
