"""M10 end-to-end test: python tests/test_end_to_end.py   (or: python -m pytest tests/)

Runs the demo workflow from PROJECT_MASTER.md Section 13 in one go, on a temporary database and a
random free port:
  start server -> run clients -> events stored -> alerts raised -> inspect every page ->
  change incident status -> "restart" server and app -> status still there.
"""
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import app as web
import client
import database
import server

EXPECTED_EVENTS = 5 + 6 + 5 + 25          # normal + repeat + scan + spike (client.SCENARIOS)
NODES = {"normal": "node-1", "repeat": "node-2", "scan": "node-3", "spike": "node-4"}


def start_server():
    """A real TCP server on a free port, in a background thread. Returns (srv, port)."""
    srv = server.Server((server.HOST, 0), server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    server.PORT = srv.server_address[1]       # so the About page checks this server
    return srv, server.PORT


def stop_server(srv):
    srv.shutdown()
    srv.server_close()


def wait_for(condition, what, seconds=5):
    """The server handles events in threads, so give it a moment to store them."""
    end = time.time() + seconds
    while time.time() < end:
        if condition():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for: {what}")


def page(web_client, path):
    r = web_client.get(path)
    assert r.status_code == 200, f"{path} -> {r.status_code}"
    return r.get_data(as_text=True)


def incident_of(source):
    found = [i for i in database.get_incidents() if i["source"] == source]
    assert len(found) == 1, f"{source}: expected 1 incident, found {len(found)}"
    return found[0]


def test_full_demo_workflow():
    old_db, old_port = database.DB_PATH, server.PORT
    database.DB_PATH = os.path.join(tempfile.mkdtemp(), "e2e.db")
    database.init_db()
    srv, port = start_server()
    try:
        # 1-2. server and dashboard are up, nothing recorded yet
        web_client = web.app.test_client()
        assert "Reachable" in page(web_client, "/about")
        assert "No events yet" in page(web_client, "/") and "No alerts yet" in page(web_client, "/alerts")

        # 3-4. clients send traffic, the server logs it
        for mode in ("normal", "repeat", "scan", "spike"):
            client.send_scenario(mode, port=port, delay=0)
        wait_for(lambda: database.get_counts()["events"] == EXPECTED_EVENTS, f"{EXPECTED_EVENTS} events")
        wait_for(lambda: database.get_counts()["alerts"] == 3, "3 alerts")
        time.sleep(0.3)                                   # a wrong extra alert would show up now
        counts = database.get_counts()
        assert counts == {"events": EXPECTED_EVENTS, "alerts": 3, "open_incidents": 3, "nodes": 4}, counts

        # 5. alerts: exactly one per attack, none for normal traffic
        rules = {a["source"]: a["rule"] for a in database.get_alerts()}
        assert rules == {"node-2": "repeated_connections", "node-3": "port_scan", "node-4": "traffic_spike"}

        # 6. every page shows the real data
        html = page(web_client, "/")
        assert f'card-value">{EXPECTED_EVENTS}<' in html and 'card-value">3<' in html
        assert 'card-value warn">3<' in html and 'card-value">4<' in html
        html = page(web_client, "/network")
        assert all(node in html for node in NODES.values()) and html.count("node-active") >= 4
        html = page(web_client, "/alerts")
        assert all(rule in html for rule in rules.values()) and "sev-high" in html
        html = page(web_client, "/logs?event_type=port_probe")
        assert html.count('data-label="Type">port_probe<') == 5 and "node-1" not in html
        assert html.count('data-label="Type">') == 5
        html = page(web_client, "/logs?severity=info")
        assert html.count('data-label="Type">normal_traffic<') == 5 + 25
        html = page(web_client, "/incidents")
        assert html.count("status-open") == 3 and "Port-scan-like activity from node-3" in html
        html = page(web_client, "/about")
        assert "Port-scan-like activity" in html and "Reachable" in html

        # 7. operator updates incidents through the web page
        scan, repeat, spike = incident_of("node-3"), incident_of("node-2"), incident_of("node-4")
        for incident, new_status in ((scan, "acknowledged"), (repeat, "contained"), (spike, "resolved")):
            r = web_client.post(f"/incidents/{incident['id']}/status", data={"status": new_status})
            assert r.status_code == 302, new_status
        statuses = {i["source"]: i["status"] for i in database.get_incidents()}
        assert statuses == {"node-3": "acknowledged", "node-2": "contained", "node-4": "resolved"}
        assert database.get_counts()["open_incidents"] == 1       # only the acknowledged one is still active

        # 8. "restart": stop the TCP server and drop the web client; start fresh ones on the same file
        stop_server(srv)
        assert "Not reachable" in page(web.app.test_client(), "/about")
        srv, port = start_server()
        web_client = web.app.test_client()
        assert "Reachable" in page(web_client, "/about")
        html = page(web_client, "/incidents")
        for status in ("acknowledged", "contained", "resolved"):
            assert f"status-{status}" in html, status
        assert {i["source"]: i["status"] for i in database.get_incidents()} == statuses

        # 9. the same attacks again after the restart
        client.send_scenario("scan", port=port, delay=0)       # node-3's incident is still active
        client.send_scenario("repeat", port=port, delay=0)     # node-2's incident was contained
        wait_for(lambda: database.get_counts()["events"] == EXPECTED_EVENTS + 5 + 6, "11 more events")
        wait_for(lambda: len([i for i in database.get_incidents() if i["source"] == "node-2"]) == 2,
                 "a NEW incident for node-2")
        assert len([i for i in database.get_incidents() if i["source"] == "node-3"]) == 1   # reused
        new_node2 = [i for i in database.get_incidents() if i["source"] == "node-2" and i["status"] == "open"]
        assert len(new_node2) == 1 and new_node2[0]["id"] != repeat["id"]
        assert database.get_incident(repeat["id"])["status"] == "contained"                  # old one untouched
        assert page(web_client, "/incidents").count("status-contained") >= 1
    finally:
        stop_server(srv)
        database.DB_PATH, server.PORT = old_db, old_port


if __name__ == "__main__":
    test_full_demo_workflow()
    print("PASS test_full_demo_workflow")
    print("M10: end-to-end workflow passed")