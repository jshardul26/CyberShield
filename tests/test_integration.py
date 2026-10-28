"""M5 tests: python tests/test_integration.py  (temporary DB, random free port).
Real client -> real TCP server -> detector -> SQLite."""
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import client
import database
import server

database.DB_PATH = os.path.join(tempfile.mkdtemp(), "test.db")
database.init_db()
srv = server.Server((server.HOST, 0), server.Handler)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()


def run(mode, source):
    client.send_scenario(mode, source, port=PORT, delay=0)
    time.sleep(0.5)


def alerts_for(source):
    return [a for a in database.get_alerts() if a["source"] == source]


def incidents_for(source):
    return [i for i in database.get_incidents() if i["source"] == source]


def test_normal_traffic_no_alert():
    run("normal", "calm-node")
    assert alerts_for("calm-node") == [] and incidents_for("calm-node") == []


def test_repeat_creates_one_alert_one_incident():
    run("repeat", "n-repeat")          # 6 attempts: 5th triggers, 6th is suppressed
    alerts, incidents = alerts_for("n-repeat"), incidents_for("n-repeat")
    assert len(alerts) == 1 and alerts[0]["rule"] == "repeated_connections"
    assert len(incidents) == 1 and incidents[0]["status"] == "open"
    assert incidents[0]["title"] == "Repeated connection attempts from n-repeat"
    assert incidents[0]["severity"] == "medium"


def test_scan_creates_high_severity_incident():
    run("scan", "n-scan")
    alerts, incidents = alerts_for("n-scan"), incidents_for("n-scan")
    assert [a["rule"] for a in alerts] == ["port_scan"]
    assert incidents[0]["severity"] == "high" and "4 different ports" in alerts[0]["description"]


def test_spike_flooding_is_suppressed():
    run("spike", "n-spike")            # 25 events, rule fires from the 20th on -> still ONE alert
    assert [a["rule"] for a in alerts_for("n-spike")] == ["traffic_spike"]
    assert len(incidents_for("n-spike")) == 1


def test_sources_are_independent():
    run("repeat", "src-a")
    run("normal", "src-b")
    assert len(alerts_for("src-a")) == 1 and alerts_for("src-b") == []


def test_acknowledged_incident_is_reused():
    run("repeat", "n-ack")
    inc = incidents_for("n-ack")[0]
    database.update_incident_status(inc["id"], "acknowledged")
    run("repeat", "n-ack")             # more attempts, same window
    assert len(incidents_for("n-ack")) == 1 and len(alerts_for("n-ack")) == 1


def test_resolved_incident_gets_new_incident():
    run("repeat", "n-res")
    first = incidents_for("n-res")[0]
    database.update_incident_status(first["id"], "resolved")
    run("repeat", "n-res")             # still >= 5 attempts in the window
    incidents = incidents_for("n-res")
    assert len(incidents) == 2 and {i["status"] for i in incidents} == {"resolved", "open"}


def test_alert_points_to_triggering_event():
    run("scan", "n-link")
    alert = alerts_for("n-link")[0]
    event = next(e for e in database.get_events(500) if e["id"] == alert["event_id"])
    assert event["source"] == "n-link" and event["event_type"] == "port_probe"


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print(f"{len(tests)} tests passed")