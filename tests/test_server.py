"""M3 tests: python tests/test_server.py  (temporary DB, random free port)."""
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import database
import server

database.DB_PATH = os.path.join(tempfile.mkdtemp(), "test.db")
database.init_db()
srv = server.Server((server.HOST, 0), server.Handler)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()


def send(*lines):
    with socket.create_connection((server.HOST, PORT)) as s:
        for line in lines:
            s.sendall(line if isinstance(line, bytes) else line.encode())
    time.sleep(0.3)


def count():
    return database.get_counts()["events"]


def test_valid_event_stored():
    before = count()
    send('{"source":"node-1","event_type":"normal_traffic","dest_port":80,"message":"hi"}\n')
    assert count() == before + 1
    row = database.get_events()[0]
    assert row["source"] == "node-1" and row["severity"] == "info"


def test_bad_input_ignored_server_survives():
    before = count()
    send("not json\n", "[1,2]\n", '{"source":"x","event_type":"hack"}\n',
         '{"source":"","event_type":"normal_traffic"}\n',
         '{"source":"x","event_type":"port_probe","dest_port":99999}\n', b"\xff\xfe\n")
    assert count() == before
    send('{"source":"node-2","event_type":"port_probe","dest_port":22}\n')
    assert count() == before + 1


def test_many_lines_one_connection():
    before = count()
    send(*['{"source":"node-3","event_type":"connection_attempt","dest_port":22}\n'] * 5)
    assert count() == before + 5


def test_multiple_clients_at_once():
    before = count()
    ts = [threading.Thread(target=send, args=(
        f'{{"source":"node-{i}","event_type":"normal_traffic"}}\n',)) for i in range(10, 20)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert count() == before + 10


def test_oversized_line_dropped():
    before = count()
    send(b"a" * (server.MAX_LINE_BYTES + 10) + b"\n")
    assert count() == before


def test_injection_string_is_plain_text():
    send('{"source":"x\'); DROP TABLE events;--","event_type":"normal_traffic"}\n')
    assert count() > 0


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for t in tests:
        t(); print("PASS", t.__name__)
    print(f"{len(tests)} tests passed")