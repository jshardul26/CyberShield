"""Rule-based detection for CyberShield.

Pure functions: no database, no sockets. The server passes in the recent events of ONE
source (the last WINDOW_SECONDS, including the newest event) and gets back a list of alerts.
"""

# ---- Thresholds (small on purpose so a demo triggers in seconds) ----
WINDOW_SECONDS = 10
REPEATED_CONNECTION_THRESHOLD = 5   # connection_attempt events from one source
PORT_SCAN_THRESHOLD = 4             # distinct destination ports probed by one source
TRAFFIC_SPIKE_THRESHOLD = 20        # events of any type from one source

# ---- Event types and the severity stored for each ----
EVENT_SEVERITY = {
    "normal_traffic": "info",
    "connection_attempt": "low",
    "port_probe": "low",
}
VALID_EVENT_TYPES = tuple(EVENT_SEVERITY)

RULE_TITLES = {
    "repeated_connections": "Repeated connection attempts",
    "port_scan": "Port-scan-like activity",
    "traffic_spike": "Traffic spike",
}

# Severity of the alert each rule raises (also shown on the About page)
RULE_SEVERITY = {
    "repeated_connections": "medium",
    "port_scan": "high",
    "traffic_spike": "medium",
}


def event_severity(event_type):
    """Severity for one stored event. Raises ValueError for unknown types."""
    if event_type not in EVENT_SEVERITY:
        raise ValueError(f"unknown event type: {event_type}")
    return EVENT_SEVERITY[event_type]


def incident_title(rule, source):
    """Same title every time for (rule, source), so the server can reuse an open incident."""
    return f"{RULE_TITLES[rule]} from {source}"


def detect(recent_events):
    """Return a list of alerts: {"rule", "severity", "description"}. Empty list = nothing suspicious.

    `recent_events` items need "event_type" and "dest_port" keys (dicts or sqlite3.Row).
    """
    alerts = []

    connection_attempts = sum(1 for e in recent_events if e["event_type"] == "connection_attempt")
    if connection_attempts >= REPEATED_CONNECTION_THRESHOLD:
        alerts.append({
            "rule": "repeated_connections",
            "severity": RULE_SEVERITY["repeated_connections"],
            "description": f"{connection_attempts} connection attempts in {WINDOW_SECONDS} s "
                           f"(threshold {REPEATED_CONNECTION_THRESHOLD})",
        })

    probed_ports = {e["dest_port"] for e in recent_events
                    if e["event_type"] == "port_probe" and e["dest_port"] is not None}
    if len(probed_ports) >= PORT_SCAN_THRESHOLD:
        alerts.append({
            "rule": "port_scan",
            "severity": RULE_SEVERITY["port_scan"],
            "description": f"{len(probed_ports)} different ports probed in {WINDOW_SECONDS} s "
                           f"(threshold {PORT_SCAN_THRESHOLD})",
        })

    if len(recent_events) >= TRAFFIC_SPIKE_THRESHOLD:
        alerts.append({
            "rule": "traffic_spike",
            "severity": RULE_SEVERITY["traffic_spike"],
            "description": f"{len(recent_events)} events in {WINDOW_SECONDS} s "
                           f"(threshold {TRAFFIC_SPIKE_THRESHOLD})",
        })

    return alerts