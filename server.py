"""CyberShield TCP server (M3). Receives one JSON line per event and stores it in SQLite.

Run:  python server.py
Detection is NOT wired in yet (that is M5).
"""
import json
import socketserver

import database
import detector

HOST = "127.0.0.1"
PORT = 9999
MAX_LINE_BYTES = 4096      # longer lines are rejected
CLIENT_TIMEOUT = 30        # seconds of silence before a connection is dropped
MAX_PORT = 65535


def parse_message(raw):
    """Validate one raw line (bytes or str). Returns a clean dict or raises ValueError."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("not valid JSON")
    if not isinstance(data, dict):
        raise ValueError("message must be a JSON object")

    source = data.get("source")
    if not isinstance(source, str) or not source.strip() or len(source) > 50:
        raise ValueError("source must be a non-empty string (max 50 chars)")

    event_type = data.get("event_type")
    if event_type not in detector.VALID_EVENT_TYPES:
        raise ValueError(f"event_type must be one of {detector.VALID_EVENT_TYPES}")

    dest_port = data.get("dest_port")
    if dest_port is not None:
        if isinstance(dest_port, bool) or not isinstance(dest_port, int) or not 0 <= dest_port <= MAX_PORT:
            raise ValueError("dest_port must be an integer 0-65535")

    message = data.get("message", "")
    if not isinstance(message, str):
        raise ValueError("message must be a string")

    return {"source": source.strip(), "event_type": event_type,
            "dest_port": dest_port, "message": message[:200]}


def process_event(event):
    """Store one validated event. Returns the new event id. (Detection is added in M5.)"""
    return database.add_event(event["source"], event["event_type"], event["dest_port"],
                              event["message"], detector.event_severity(event["event_type"]))


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(CLIENT_TIMEOUT)
        peer = self.client_address[1]
        try:
            while True:
                raw = self.rfile.readline(MAX_LINE_BYTES + 1)
                if not raw:
                    break                                   # client closed the connection
                if len(raw) > MAX_LINE_BYTES:
                    print(f"[{peer}] line too long, dropping connection")
                    break
                if not raw.strip():
                    continue
                try:
                    event = parse_message(raw)
                    event_id = process_event(event)
                    print(f"[{peer}] stored event #{event_id}: {event['source']} {event['event_type']}")
                except ValueError as err:
                    print(f"[{peer}] rejected: {err}")
        except (OSError, TimeoutError):
            pass                                            # reset or timeout: just end this thread


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    database.init_db()
    with Server((HOST, PORT), Handler) as srv:
        print(f"CyberShield server listening on {HOST}:{PORT}  (Ctrl+C to stop)")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nStopping.")


if __name__ == "__main__":
    main()