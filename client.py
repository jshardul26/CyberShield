"""CyberShield simulated client (M4). Sends one JSON line per event to the TCP server.

Usage:  python client.py <normal|repeat|scan|spike|all> [--source NAME]

Everything is sent to 127.0.0.1 only. Events are synthetic: nothing is scanned or attacked.
"""
import argparse
import json
import socket
import sys
import time

HOST = "127.0.0.1"
PORT = 9999

# mode: (default source, event_type, ports to use, message text, delay between events in seconds)
SCENARIOS = {
    "normal": ("node-1", "normal_traffic", [80, 443, 53, 80, 443], "regular web/DNS traffic", 0.5),
    "repeat": ("node-2", "connection_attempt", [22] * 6, "repeated login attempt", 0.2),
    "scan": ("node-3", "port_probe", [21, 22, 23, 80, 443], "probing port", 0.2),
    "spike": ("node-4", "normal_traffic", [80] * 25, "burst of requests", 0.05),
}


def send_scenario(mode, source=None, host=HOST, port=PORT, delay=None):
    """Send all events of one scenario over ONE TCP connection. Returns the number sent."""
    default_source, event_type, ports, text, default_delay = SCENARIOS[mode]
    source = source or default_source
    delay = default_delay if delay is None else delay

    with socket.create_connection((host, port), timeout=5) as conn:
        for i, dest_port in enumerate(ports, start=1):
            event = {"source": source, "event_type": event_type,
                     "dest_port": dest_port, "message": f"{text} #{i}"}
            conn.sendall((json.dumps(event) + "\n").encode("utf-8"))
            time.sleep(delay)
    return len(ports)


def main():
    parser = argparse.ArgumentParser(description="CyberShield simulated network client")
    parser.add_argument("mode", choices=list(SCENARIOS) + ["all"])
    parser.add_argument("--source", help="node name (default depends on the mode)")
    args = parser.parse_args()

    modes = list(SCENARIOS) if args.mode == "all" else [args.mode]
    try:
        for mode in modes:
            sent = send_scenario(mode, args.source)
            print(f"{mode}: sent {sent} events")
    except OSError as err:
        print(f"Cannot reach the server at {HOST}:{PORT} ({err}). Start it first: python server.py")
        sys.exit(1)


if __name__ == "__main__":
    main()