from importlib import resources

import pytest

from helpers import DASH_KEY as KEY, http_call as call, start_dashboard


@pytest.fixture
def dash(tmp_path, key):
    app, base, srv = start_dashboard(tmp_path, key)
    yield app, base
    srv.shutdown()


def test_page_sets_session_cookie_and_csp(dash):
    _, base = dash
    code, headers, body = call(base + f"/?key={KEY}")
    assert code == 200 and b"Chain of custody" in body
    assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
    assert headers["Content-Security-Policy"].startswith("default-src 'self'")
    for asset, ctype in (("/app.js", "text/javascript"), ("/app.css", "text/css")):
        code, headers, _ = call(base + asset, headers={"cookie": f"poi_session={KEY}"})
        assert code == 200 and headers["Content-Type"].startswith(ctype)


def test_static_js_never_parses_html():
    js = (resources.files("poi") / "dashboard_static" / "app.js").read_text()
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", 'setAttribute("style"'):
        assert banned not in js, banned


def test_page_loads_no_external_resources():
    html = (resources.files("poi") / "dashboard_static" / "index.html").read_text()
    assert "http://" not in html and "https://" not in html
    assert "<script>" not in html                      # no inline script: CSP forbids it
