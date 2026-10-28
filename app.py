"""CyberShield web dashboard (Flask). Reads the SQLite database filled by server.py.

Run: python app.py   then open http://127.0.0.1:5000
"""
import os
import socket
import subprocess
import sys

from flask import Flask, abort, redirect, render_template, request, url_for

import database
import detector
import server

HOST = "127.0.0.1"
PORT = 5000
CLIENT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client.py")
SIMULATION_TIMEOUT = 30    # seconds; `client.py all` takes about 6 s

app = Flask(__name__)

# (endpoint, label) in menu order. A link only appears once its page exists.
NAV = [("dashboard", "Dashboard"), ("network", "Network"), ("alerts", "Alerts"),
       ("incidents", "Incidents"), ("logs", "Logs"), ("about", "About")]

# Messages for the "Run simulation" result. The URL only carries a key from this fixed dict.
SIM_MESSAGES = {
    "ok": ("ok", "Simulation finished: normal, repeat, scan and spike traffic was sent."),
    "down": ("error", "Could not reach the server. Start it first: python server.py"),
    "failed": ("error", "The simulation did not finish. Check the client and server."),
}


# Incident workflow: an incident may only move forward (button label shown on the page too).
NEXT_STATUSES = {
    "open": ("acknowledged", "contained", "resolved"),
    "acknowledged": ("contained", "resolved"),
    "contained": ("resolved",),
    "resolved": (),
}
ACTION_LABELS = {"acknowledged": "Acknowledge", "contained": "Contain", "resolved": "Resolve"}


@app.context_processor
def inject_navigation():
    pages = set(app.view_functions)
    return {"nav": [(url_for(ep), label) for ep, label in NAV if ep in pages], "pages": pages}


@app.route("/")
def dashboard():
    return render_template(
        "dashboard.html",
        counts=database.get_counts(),
        events=database.get_events(limit=10),
        alerts=database.get_alerts(limit=5),
    )


@app.route("/network")
def network():
    sim = SIM_MESSAGES.get(request.args.get("sim"))
    return render_template(
        "network.html",
        nodes=database.get_nodes(),
        events=database.get_events(limit=15),
        sim=sim,
    )


@app.route("/network/simulate", methods=["POST"])
def simulate():
    """Run `client.py all` with FIXED arguments (decision D4): nothing from the request is used."""
    try:
        result = subprocess.run([sys.executable, CLIENT_PATH, "all"], capture_output=True,
                                timeout=SIMULATION_TIMEOUT, cwd=os.path.dirname(CLIENT_PATH))
        outcome = "ok" if result.returncode == 0 else "down" if result.returncode == 1 else "failed"
    except (subprocess.TimeoutExpired, OSError):
        outcome = "failed"
    return redirect(url_for("network", sim=outcome))


@app.route("/alerts")
def alerts():
    return render_template("alerts.html", alerts=database.get_alerts(limit=100))


@app.route("/incidents")
def incidents():
    return render_template("incidents.html", incidents=database.get_incidents(),
                           next_statuses=NEXT_STATUSES, labels=ACTION_LABELS)


@app.route("/incidents/<int:incident_id>/status", methods=["POST"])
def change_incident_status(incident_id):
    """Move one incident forward. Unknown id -> 404; invalid or backward status -> 400."""
    incident = database.get_incident(incident_id)
    if incident is None:
        abort(404)
    new_status = request.form.get("status", "")
    if new_status not in NEXT_STATUSES[incident["status"]]:
        abort(400)
    database.update_incident_status(incident_id, new_status)
    return redirect(url_for("incidents") + f"#incident-{incident_id}")


def server_reachable():
    """True if something accepts TCP connections on the server's host:port.

    Connects and closes at once without sending anything, so no event is stored. The address
    comes from server.py's constants, never from the request.
    """
    try:
        with socket.create_connection((server.HOST, server.PORT), timeout=1):
            return True
    except OSError:
        return False


def detection_rules():
    """The three rules with their CURRENT thresholds (read from detector.py, not copied)."""
    window = detector.WINDOW_SECONDS
    titles, severity = detector.RULE_TITLES, detector.RULE_SEVERITY
    return [
        {"title": titles["repeated_connections"], "severity": severity["repeated_connections"],
         "trigger": f"{detector.REPEATED_CONNECTION_THRESHOLD} or more connection_attempt events "
                    f"from one source within {window} s"},
        {"title": titles["port_scan"], "severity": severity["port_scan"],
         "trigger": f"{detector.PORT_SCAN_THRESHOLD} or more different destination ports in "
                    f"port_probe events from one source within {window} s"},
        {"title": titles["traffic_spike"], "severity": severity["traffic_spike"],
         "trigger": f"{detector.TRAFFIC_SPIKE_THRESHOLD} or more events of any type "
                    f"from one source within {window} s"},
    ]


@app.route("/about")
def about():
    return render_template("about.html", reachable=server_reachable(), server_host=server.HOST,
                           server_port=server.PORT, rules=detection_rules(),
                           event_types=detector.VALID_EVENT_TYPES)


@app.route("/logs")
def logs():
    event_type = request.args.get("event_type", "")
    severity = request.args.get("severity", "")
    ignored = []                                   # invalid filter values are dropped, not used
    if event_type and event_type not in detector.VALID_EVENT_TYPES:
        event_type = ""
        ignored.append("event type")
    if severity and severity not in database.SEVERITIES:
        severity = ""
        ignored.append("severity")
    return render_template(
        "logs.html",
        events=database.get_events(limit=100, event_type=event_type or None, severity=severity or None),
        event_types=detector.VALID_EVENT_TYPES,
        severities=database.SEVERITIES,
        selected_type=event_type,
        selected_severity=severity,
        ignored=ignored,
    )


if __name__ == "__main__":
    database.init_db()
    app.run(host=HOST, port=PORT, debug=False)