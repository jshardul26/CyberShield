"""M6 tests: python tests/test_app.py  (Flask test client, temporary DB)."""
import os
import socket
import sys
import tempfile
import threading
import time
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


# ---------- M8: /incidents and status changes ----------

def make_incident(title="Port-scan-like activity from node-3", source="node-3", severity="high"):
    """Incident with one alert, as the server would create it. Returns the incident id."""
    event_id = database.add_event(source, "port_probe", 22, "probe", "low")
    incident_id = database.add_incident(title, source, severity)
    database.add_alert(event_id, incident_id, "port_scan", "4 ports", severity)
    return incident_id


def set_status(incident_id, status):
    return c.post(f"/incidents/{incident_id}/status", data={"status": status})


def test_incidents_empty_and_in_nav():
    with EmptyDatabase():
        html = get("/incidents")
        assert "No incidents yet" in html and 'href="/incidents"' in html


def test_incidents_page_lists_rows_and_buttons():
    with EmptyDatabase():
        first = make_incident()
        second = make_incident("Traffic spike from node-4", "node-4", "medium")
        html = get("/incidents")
        assert f'id="incident-{first}"' in html and f'id="incident-{second}"' in html
        assert "Traffic spike from node-4" in html and "sev-medium" in html and "status-open" in html
        assert f'action="/incidents/{first}/status"' in html
        assert "Acknowledge" in html and "Contain" in html and "Resolve" in html
        assert f'href="/incidents#incident-{first}"' in get("/alerts")      # alerts page links here


def test_buttons_follow_the_current_status():
    with EmptyDatabase():
        i = make_incident()
        assert set_status(i, "acknowledged").status_code == 302
        html = get("/incidents")
        assert "Acknowledge" not in html and "Contain" in html and "Resolve" in html
        set_status(i, "contained")
        html = get("/incidents")
        assert "Contain<" not in html and "Resolve" in html
        set_status(i, "resolved")
        html = get("/incidents")
        assert "Resolve<" not in html and "Closed" in html and "status-resolved" in html


def test_status_change_persists_and_updates_other_pages():
    with EmptyDatabase():
        i = make_incident()
        assert database.get_counts()["open_incidents"] == 1
        r = set_status(i, "acknowledged")
        assert r.status_code == 302 and r.headers["Location"].endswith(f"/incidents#incident-{i}")
        assert database.get_incident(i)["status"] == "acknowledged"          # saved in SQLite
        fresh_client = web.app.test_client()                                  # like a page refresh/restart
        assert "status-acknowledged" in fresh_client.get("/incidents").get_data(as_text=True)
        assert "status-acknowledged" in get("/alerts")                        # alert shows incident status
        assert database.get_counts()["open_incidents"] == 1                   # acknowledged is still active
        set_status(i, "resolved")
        assert database.get_counts()["open_incidents"] == 0
        assert 'card-value">0<' in get("/")


def test_incident_only_moves_forward():
    with EmptyDatabase():
        i = make_incident()
        set_status(i, "contained")
        for bad in ("open", "acknowledged", "contained"):                    # backward or same
            assert set_status(i, bad).status_code == 400, bad
        assert database.get_incident(i)["status"] == "contained"
        assert set_status(i, "resolved").status_code == 302
        for bad in ("open", "acknowledged", "contained", "resolved"):        # resolved is final
            assert set_status(i, bad).status_code == 400, bad
        assert database.get_incident(i)["status"] == "resolved"
        j = make_incident()
        assert set_status(j, "resolved").status_code == 302                  # open can jump ahead


def test_bad_status_requests_are_rejected_safely():
    with EmptyDatabase():
        i = make_incident()
        assert set_status(i, "deleted").status_code == 400
        assert set_status(i, "").status_code == 400
        assert set_status(i, "resolved'; DROP TABLE incidents;--").status_code == 400
        assert c.post(f"/incidents/{i}/status").status_code == 400            # field missing
        assert set_status(999, "resolved").status_code == 404                 # unknown incident
        assert c.post("/incidents/abc/status", data={"status": "resolved"}).status_code == 404
        assert c.get(f"/incidents/{i}/status").status_code == 405             # POST only
        assert database.get_incident(i)["status"] == "open"                   # nothing changed, table intact


def test_incident_text_is_escaped():
    with EmptyDatabase():
        make_incident("<b>x</b>", "<script>alert(1)</script>", "low")
        html = get("/incidents")
        assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html and "<b>x</b>" not in html


# ---------- M9: /about ----------

class ServerPort:
    """Point the About page's reachability check at a port, then restore the real one."""
    def __init__(self, port):
        self.port = port

    def __enter__(self):
        self.old = web.server.PORT
        web.server.PORT = self.port

    def __exit__(self, *exc):
        web.server.PORT = self.old


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                  # nothing listens here any more
    return port


class LiveServer:
    """A real CyberShield TCP server on a free port, for the 'reachable' case."""
    def __enter__(self):
        self.srv = web.server.Server(("127.0.0.1", 0), web.server.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]
        self.port_ctx = ServerPort(self.port)
        self.port_ctx.__enter__()
        return self

    def __exit__(self, *exc):
        self.port_ctx.__exit__()
        self.srv.shutdown()
        self.srv.server_close()


def test_about_in_nav_and_explains_the_project():
    with EmptyDatabase():
        html = get("/about")
        assert 'href="/about"' in html
        assert "Simulation only" in html and "127.0.0.1" in html and "not</strong> detect all real-world" in html
        for part in ("client.py", "server.py", "detector.py", "SQLite", "Flask"):
            assert part in html


def test_about_server_not_reachable():
    with ServerPort(closed_port()):
        html = get("/about")
    assert "server-down" in html and "Not reachable" in html and "python server.py" in html
    assert "server-up" not in html


def test_about_server_reachable_and_check_stores_nothing():
    with EmptyDatabase():
        with LiveServer() as live:
            html = get("/about")
            assert "server-up" in html and "server-down" not in html and f"127.0.0.1:{live.port}" in html
            assert "python server.py" not in html
            get("/about")
            time.sleep(0.2)                                  # let the server thread see the closed connection
        assert database.get_counts()["events"] == 0          # the check sent no event


def test_about_address_cannot_be_changed_from_the_request():
    with LiveServer():
        html = get("/about?host=10.9.8.7&port=1&server_port=1")
        assert "server-up" in html and "10.9.8.7" not in html


def test_about_rules_come_from_detector_constants():
    html = get("/about")
    for title in web.detector.RULE_TITLES.values():
        assert title in html
    assert "sev-high" in html and "sev-medium" in html
    old = web.detector.PORT_SCAN_THRESHOLD
    web.detector.PORT_SCAN_THRESHOLD = 7
    try:
        assert "7 or more different destination ports" in get("/about")
    finally:
        web.detector.PORT_SCAN_THRESHOLD = old
    assert f"{web.detector.REPEATED_CONNECTION_THRESHOLD} or more connection_attempt" in get("/about")
    assert f"{web.detector.TRAFFIC_SPIKE_THRESHOLD} or more events of any type" in get("/about")


def test_tables_are_ready_for_phone_cards():
    with EmptyDatabase():
        make_incident()
        pages = {"/": 2, "/network": 2, "/alerts": 1, "/incidents": 1, "/logs": 1, "/about": 1}
        for path, tables in pages.items():
            html = get(path)
            if path in ("/", "/network"):
                database.add_event("node-1", "normal_traffic", 80, "x", "info")
                html = get(path)
            assert html.count('<table class="stack">') >= 1, path
            assert 'data-label="' in html, path
        html = get("/incidents")
        for label in ("ID", "Created (UTC)", "Source", "Title", "Severity", "Alerts", "Status", "Actions"):
            assert f'data-label="{label}"' in html, label
        assert html.count("<td") == html.count("data-label=")          # every cell has a label
    css = c.get("/static/css/style.css").get_data(as_text=True)
    assert "table.stack td::before" in css and "attr(data-label)" in css


def test_long_text_cells_can_wrap():
    with EmptyDatabase():
        make_incident()
        database.add_event("node-1", "normal_traffic", 80, "m" * 150, "info")
        assert 'class="wrap"' in get("/alerts") and 'class="wrap"' in get("/logs")
        assert 'class="wrap"' in get("/incidents")
    assert "td.wrap" in c.get("/static/css/style.css").get_data(as_text=True)


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print(f"{len(tests)} tests passed")