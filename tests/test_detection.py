"""M2 tests. Run from the CyberShield folder with either:
    python tests/test_detection.py
    python -m pytest tests/
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import detector as d


def make(event_type, count, ports=None):
    """Build `count` fake events. `ports` is a list of ports cycled through."""
    ports = ports or [80]
    return [{"event_type": event_type, "dest_port": ports[i % len(ports)]} for i in range(count)]


def rules(events):
    return [a["rule"] for a in d.detect(events)]


# ---- repeated connections ----
def test_repeated_connections_below_threshold():
    assert rules(make("connection_attempt", 4)) == []


def test_repeated_connections_at_threshold():
    assert rules(make("connection_attempt", 5)) == ["repeated_connections"]


def test_repeated_connections_ignores_other_types():
    assert rules(make("normal_traffic", 10)) == []


# ---- port scan ----
def test_port_scan_below_threshold():
    assert rules(make("port_probe", 3, [21, 22, 23])) == []


def test_port_scan_at_threshold():
    assert rules(make("port_probe", 4, [21, 22, 23, 80])) == ["port_scan"]


def test_port_scan_needs_distinct_ports():
    assert rules(make("port_probe", 10, [22])) == []


def test_port_scan_ignores_normal_traffic_ports():
    assert rules(make("normal_traffic", 6, [80, 443, 22, 25, 53, 110])) == []


def test_port_scan_ignores_missing_port():
    assert rules(make("port_probe", 6, [None])) == []


# ---- traffic spike ----
def test_traffic_spike_below_threshold():
    assert rules(make("normal_traffic", 19)) == []


def test_traffic_spike_at_threshold():
    assert rules(make("normal_traffic", 20)) == ["traffic_spike"]


# ---- combined / edge cases ----
def test_empty_list():
    assert d.detect([]) == []


def test_two_rules_at_once():
    events = make("port_probe", 20, list(range(1, 21)))
    assert rules(events) == ["port_scan", "traffic_spike"]


def test_alert_fields_and_severity():
    alert = d.detect(make("port_probe", 4, [1, 2, 3, 4]))[0]
    assert alert["severity"] == "high"
    assert "4 different ports" in alert["description"]


# ---- helpers ----
def test_event_severity():
    assert d.event_severity("normal_traffic") == "info"
    assert d.event_severity("port_probe") == "low"


def test_event_severity_unknown_type():
    try:
        d.event_severity("hack")
        assert False, "should have raised"
    except ValueError:
        pass


def test_incident_title_is_stable():
    assert d.incident_title("port_scan", "node-2") == "Port-scan-like activity from node-2"
    assert d.incident_title("port_scan", "node-2") == d.incident_title("port_scan", "node-2")


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    for name, func in tests:
        func()
        print("PASS ", name)
    print(f"\nM2: all {len(tests)} tests passed")