"""M1 acceptance test. Run from the CyberShield folder:  python tests/test_database.py
Uses a temporary database file, so your real cybershield.db is never touched."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import database as db

tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp.close()
db.DB_PATH = tmp.name


def check(name, condition):
    print(("PASS  " if condition else "FAIL  ") + name)
    if not condition:
        sys.exit(1)


db.init_db()
db.init_db()  # calling twice must be safe
check("init_db is repeatable", True)

# events
e1 = db.add_event("node-1", "normal_traffic", 80, "hello")
e2 = db.add_event("node-2", "port_probe", 22, "probe", "low")
check("add_event returns ids", (e1, e2) == (1, 2))
check("get_events newest first", db.get_events()[0]["id"] == e2)
check("filter by event_type", len(db.get_events(event_type="port_probe")) == 1)
check("filter by severity", len(db.get_events(severity="low")) == 1)
check("recent events window", len(db.get_recent_events("node-1", 10)) == 1)
check("other source not included", len(db.get_recent_events("node-9", 10)) == 0)

# incidents + alerts
inc = db.add_incident("Port scan from node-2", "node-2", "high")
db.add_alert(e2, inc, "port_scan", "4 ports in 10 s", "high")
check("find_active_incident finds it", db.find_active_incident("node-2", "Port scan from node-2")["id"] == inc)
check("alert joined with incident status", db.get_alerts()[0]["status"] == "open")
check("incident alert_count", db.get_incidents()[0]["alert_count"] == 1)

# status changes
check("acknowledge works", db.update_incident_status(inc, "acknowledged"))
check("still active when acknowledged", db.find_active_incident("node-2", "Port scan from node-2") is not None)
check("resolve works", db.update_incident_status(inc, "resolved"))
check("resolved is not active", db.find_active_incident("node-2", "Port scan from node-2") is None)
check("unknown incident id returns False", db.update_incident_status(999, "resolved") is False)

# validation
for bad in (lambda: db.add_event("n", "t", 1, "m", "critical"),
            lambda: db.update_incident_status(inc, "deleted")):
    try:
        bad()
        check("invalid value rejected", False)
    except ValueError:
        check("invalid value rejected", True)

# foreign key enforced
try:
    db.add_alert(999, 999, "r", "d", "low")
    check("foreign key enforced", False)
except Exception:
    check("foreign key enforced", True)

# SQL injection stays plain text
db.add_event("x'; DROP TABLE events;--", "normal_traffic", None, "test")
check("parameterized SQL (events table survives)", len(db.get_events()) == 3)

# dashboard helpers
counts = db.get_counts()
check("counts", counts == {"events": 3, "alerts": 1, "open_incidents": 0, "nodes": 3})
check("nodes are Active", all(n["status"] == "Active" for n in db.get_nodes()))

# persistence: data survives after a fresh connection
check("data persists across connections", len(db.get_events()) == 3)

os.remove(tmp.name)
print("\nM1: all checks passed")