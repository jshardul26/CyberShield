"""M4 tests: python tests/test_client.py  (temporary DB, random free port).
Runs each client scenario against a real server, then checks what the detector makes of it."""
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import client
import database
import detector
import server

database.DB_PATH = os.path.join(tempfile.mkdtemp(), "test.db")
database.init_db()
srv = server.Server((server.HOST, 0), server.Handler)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()


def run(mode, source=None):
    sent = client.send_scenario(mode, source, port=PORT, delay=0)
    time.sleep(0.4)  # let the server thread finish storing
    return sent


def stored(source):
    return database.get_recent_events(source, 10)


def rules_for(source):
    return [a["rule"] for a in detector.detect(stored(source))]


def test_normal():
    assert run("normal") == 5
    rows = stored("node-1")
    assert len(rows) == 5 and {r["event_type"] for r in rows} == {"normal_traffic"}
    assert rules_for("node-1") == []


def test_repeat():
    assert run("repeat") == 6
    assert {r["event_type"] for r in stored("node-2")} == {"connection_attempt"}
    assert rules_for("node-2") == ["repeated_connections"]


def test_scan():
    assert run("scan") == 5
    assert len({r["dest_port"] for r in stored("node-3")}) == 5
    assert rules_for("node-3") == ["port_scan"]


def test_spike():
    assert run("spike") == 25
    assert len(stored("node-4")) == 25
    assert rules_for("node-4") == ["traffic_spike"]


def test_custom_source():
    run("scan", "lab-pc")
    assert len(stored("lab-pc")) == 5


def test_server_down_raises_oserror():
    s = socket.socket()
    s.bind((server.HOST, 0))
    dead_port = s.getsockname()[1]
    s.close()  # nothing is listening on this port now
    try:
        client.send_scenario("normal", port=dead_port, delay=0)
        assert False, "should have raised"
    except OSError:
        pass


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print(f"{len(tests)} tests passed")