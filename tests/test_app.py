"""M6 tests: python tests/test_app.py  (Flask test client, temporary DB)."""
import os
import sys
import tempfile
from html import escape

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import app as web
import database

database.DB_PATH = os.path.join(tempfile.mkdtemp(), "test.db")
database.init_db()
c = web.app.test_client()


def page():
    r = c.get("/")
    assert r.status_code == 200
    return r.get_data(as_text=True)


def test_empty_database_renders():
    html = page()
    assert "Dashboard" in html and "No events yet" in html and "No alerts yet" in html
    assert 'card-value">0<' in html


def test_dashboard_shows_real_data():
    e1 = database.add_event("node-9", "normal_traffic", 80, "hello", "info")
    e2 = database.add_event("node-3", "port_probe", 22, "probe", "low")
    inc = database.add_incident("Port-scan-like activity from node-3", "node-3", "high")
    database.add_alert(e2, inc, "port_scan", "4 ports", "high")
    html = page()
    assert "node-9" in html and "port_probe" in html and "port_scan" in html
    assert "sev-high" in html and "sev-info" in html and "status-open" in html
    assert 'card-value">2<' in html            # events
    assert 'card-value warn">1<' in html       # open incidents highlighted
    assert "No events yet" not in html and e1 == 1


def test_untrusted_text_is_escaped():
    database.add_event("<script>alert(1)</script>", "normal_traffic", None, "x", "info")
    html = page()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_navigation_lists_only_existing_pages():
    html = page()
    assert 'href="/"' in html
    for ep, _ in web.NAV:
        if ep not in web.app.view_functions:
            assert f'href="/{ep}"' not in html


def test_css_served_and_unknown_page_404():
    assert c.get("/static/css/style.css").status_code == 200
    assert c.get("/no-such-page").status_code == 404


# ---------- M7: /network, /alerts, /logs ----------

class EmptyDatabase:
    """Context manager: run a block against a fresh, empty database, then switch back."""
    def __enter__(self):
        self.old = database.DB_PATH
        database.DB_PATH = os.path.join(tempfile.mkdtemp(), "empty.db")
        database.init_db()

    def __exit__(self, *exc):
        database.DB_PATH = self.old


def get(path):
    r = c.get(path)
    assert r.status_code == 200, f"{path} -> {r.status_code}"
    return r.get_data(as_text=True)


def test_nav_has_new_pages():
    html = get("/")
    for path in ("/network", "/alerts", "/logs"):
        assert f'href="{path}"' in html


def test_empty_database_new_pages():
    with EmptyDatabase():
        assert "No nodes yet" in get("/network") and "No events yet" in get("/network")
        assert "No alerts yet" in get("/alerts")
        assert "No events yet" in get("/logs")


def test_network_page_matches_database():
    html = get("/network")
    nodes = database.get_nodes()
    assert len(nodes) >= 2
    for n in nodes:
        assert escape(n["source"]) in html
    assert "node-active" in html and "Run simulation" in html
    assert 'method="post"' in html and 'action="/network/simulate"' in html


def test_alerts_page_matches_database():
    html = get("/alerts")
    alerts = database.get_alerts()
    assert len(alerts) == 1
    assert "port_scan" in html and "4 ports" in html and "node-3" in html
    assert "sev-high" in html and "status-open" in html and "#1" in html


def test_logs_shows_all_without_filter():
    html = get("/logs")
    assert "node-9" in html and "node-3" in html and "hello" in html


def test_logs_filter_by_type_severity_and_both():
    only_probe = get("/logs?event_type=port_probe")
    assert "node-3" in only_probe and "node-9" not in only_probe
    only_info = get("/logs?severity=info")
    assert "node-9" in only_info and "node-3" not in only_info
    both = get("/logs?event_type=port_probe&severity=info")
    assert "No events match this filter" in both
    assert '<option value="port_probe" selected>' in only_probe


def test_logs_invalid_filter_is_ignored_safely():
    html = get("/logs?event_type=x' OR '1'='1&severity=<b>bad</b>")
    assert "Ignored an invalid filter value" in html
    assert "node-9" in html and "node-3" in html          # behaves like no filter
    assert "<b>bad</b>" not in html and "OR '1'='1" not in html
    assert len(database.get_events()) >= 3                 # tables still intact


class FakeRun:
    """Stands in for subprocess.run so no real client is started."""
    def __init__(self, returncode=0, error=None):
        self.returncode, self.error, self.calls = returncode, error, []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error:
            raise self.error
        return self

    def install(self):
        self.original = web.subprocess.run
        web.subprocess.run = self
        return self

    def restore(self):
        web.subprocess.run = self.original


def test_simulate_runs_fixed_command_only():
    fake = FakeRun(0).install()
    try:
        r = c.post("/network/simulate", data={"mode": "evil; rm -rf /", "source": "x", "args": "--all"})
    finally:
        fake.restore()
    assert r.status_code == 302 and r.headers["Location"].endswith("/network?sim=ok")
    args, kwargs = fake.calls[0]
    assert args == [sys.executable, web.CLIENT_PATH, "all"]     # nothing from the request
    assert not kwargs.get("shell") and kwargs.get("timeout") == web.SIMULATION_TIMEOUT


def test_simulate_failure_outcomes():
    cases = [(FakeRun(1), "down"), (FakeRun(2), "failed"),
             (FakeRun(error=web.subprocess.TimeoutExpired("client.py", 30)), "failed"),
             (FakeRun(error=OSError("no python")), "failed")]
    for fake, expected in cases:
        fake.install()
        try:
            r = c.post("/network/simulate")
        finally:
            fake.restore()
        assert r.headers["Location"].endswith(f"/network?sim={expected}"), expected


def test_simulate_only_accepts_post_and_shows_result():
    assert c.get("/network/simulate").status_code == 405
    assert "Simulation finished" in get("/network?sim=ok")
    assert "Start it first" in get("/network?sim=down")
    assert "Simulation finished" not in get("/network?sim=<script>")
    assert "notice" not in get("/network")


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print(f"{len(tests)} tests passed")