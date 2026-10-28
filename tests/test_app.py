"""M6 tests: python tests/test_app.py  (Flask test client, temporary DB)."""
import os
import sys
import tempfile

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


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print(f"{len(tests)} tests passed")