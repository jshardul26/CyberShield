# PROJECT_MASTER.md — CyberShield

> Single source of truth across Claude chats. Read this FIRST in every new chat. Never assume a milestone is done unless it is marked ✅ here AND the code confirms it.

**Last updated:** 2026-10-21 (M2 complete)
**Current milestone:** M2 done ✅ → M3 next
**Next step:** M3 — write `server.py` (threaded TCP server, JSON-line parsing, validation, stores events via `database.add_event`; NO detection wiring yet, that is M5) + a small manual test using a throwaway socket script or `nc`

---

## 1. Objective

CyberShield is a beginner-friendly **Computer Networks** project: a local simulator where multiple client programs send normal/suspicious event messages over **TCP** to a monitoring server. The server applies simple rules, stores events/alerts/incidents in **SQLite**, and a **Flask** dashboard lets an operator view activity and manage incident status.

**Simulation only.** All traffic is localhost (127.0.0.1). No real scanning, attacking, or blocking. Does not claim to detect all real-world attacks.

## 2. Mandatory Requirements → Where Satisfied

| Requirement | Satisfied by |
|---|---|
| Socket programming | `server.py` (TCP server), `client.py` (simulated nodes) |
| Database management | `database.py` (SQLite: events, alerts, incidents) |
| Web development | `app.py` + `templates/` + `static/css` |
| Cybersecurity | `detector.py` (3 rules) + incident workflow |

## 3. Constraints

- Allowed: Python, Flask, `socket`, `threading`, `sqlite3`, HTML, CSS, minimal JS
- Not allowed: React, MySQL, ML, WebSockets, extra dependencies (only `flask` + `pytest` optional)
- Updates via normal page refresh; parameterized SQL only; short readable files; no decorative buttons

## 4. Architecture

```
 client.py (nodes)          server.py (TCP, port 9999)           app.py (Flask, port 5000)
 ┌──────────────┐  JSON\n   ┌────────────────────────┐          ┌─────────────────────┐
 │ node-1..N    │ ────────▶ │ accept → parse → store │          │ routes → templates  │
 │ normal/attack│   TCP     │        │               │          │ POST status updates │
 └──────────────┘           │        ▼               │          └──────────┬──────────┘
                            │   detector.py          │                     │
                            │   (3 rules)            │                     │
                            └───────────┬────────────┘                     │
                                        ▼                                  ▼
                                 ┌────────────────────────────────────────────┐
                                 │          SQLite  (cybershield.db)          │
                                 │      via database.py (shared by both)      │
                                 └────────────────────────────────────────────┘
```

**Data flow**
1. Client sends one JSON line: `{"source","event_type","dest_port","message"}`
2. Server reads until `\n`, validates, stores event
3. Detector checks recent events for that source → returns 0..n alerts
4. Server stores alert; creates/links an incident (status `open`)
5. Flask reads DB and renders pages; operator updates incident status → saved in SQLite

**Process model:** 2 separate processes (`python server.py`, `python app.py`) sharing the SQLite file. Optional `/network` "Run simulation" button launches `client.py` via `subprocess` with fixed, hard-coded arguments (no user input in the command).

## 5. Message Format (TCP)

One JSON object per line, UTF-8, terminated by `\n`.

```json
{"source": "node-3", "event_type": "connection_attempt", "dest_port": 22, "message": "login attempt"}
```

Valid `event_type`: `normal_traffic`, `connection_attempt`, `port_probe`.

## 6. Database Schema (proposed)

```
events (id PK, timestamp, source, event_type, dest_port, message, severity)
alerts (id PK, event_id FK→events, incident_id FK→incidents, rule, description, severity, timestamp)
incidents (id PK, title, source, severity, created_at, status)
```

Relationships: **1 incident ← many alerts**, **1 alert → 1 triggering event**.
Values — severity: `info | low | medium | high`; incident status: `open | acknowledged | contained | resolved`.

## 7. Detection Rules (proposed thresholds — configurable constants in `detector.py`)

| Rule | Trigger | Severity |
|---|---|---|
| Repeated connections | ≥ 5 `connection_attempt` from same source in 10 s | medium |
| Port-scan-like | ≥ 4 distinct `dest_port` from same source in 10 s | high |
| Traffic spike | ≥ 20 events (any type) from same source in 10 s | medium |

Alert de-duplication: one open incident per (source, rule); further matches attach to it.

## 8. Pages

| Route | Purpose | Actions |
|---|---|---|
| `/` | Dashboard: 4 cards, recent events, latest alerts | links |
| `/network` | Nodes + status, recent events | run simulation (fixed args) |
| `/alerts` | Alert list, info vs suspicious | link to incident |
| `/incidents` | Incident list | acknowledge / contain / resolve (POST) |
| `/logs` | Event table | filter by type/severity (GET params) |
| `/about` | Architecture + simulation-only model | shows server reachable/not |

## 9. Folder Structure

```text
CyberShield/
├── app.py
├── server.py
├── client.py
├── detector.py
├── database.py
├── requirements.txt
├── PROJECT_MASTER.md
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── network.html
│   ├── alerts.html
│   ├── incidents.html
│   ├── logs.html
│   └── about.html
├── static/
│   ├── css/style.css
│   └── js/main.js          # created ONLY if needed (currently not planned)
└── tests/
    ├── test_database.py    # added in M1 (plain-assert script)
    └── test_detection.py
```

`cybershield.db` is auto-created at runtime (git-ignored).

## 10. Decisions (D1–D8 APPROVED by user on 2026-10-21)

| # | Decision | Proposed | Why |
|---|---|---|---|
| D1 | Ports | TCP 9999, Flask 5000 | Simple, configurable via constants |
| D2 | Node status | "Active" if event seen in last 60 s, else "Idle" (derived from events, no extra table) | Avoids extra table |
| D3 | Detection window | Query last 10 s of events from DB | Stateless server, easy to explain and test |
| D4 | Run simulation button | Include, using `subprocess` with fixed args | Meets "launch simulation" without shell input |
| D5 | `main.js` | Skip unless needed | Spec says JS only if necessary |
| D6 | Alert → incident | Auto-create incident per (source, rule) | Keeps flow simple |
| D7 | Event timestamps | Server-generated UTC ISO string | Clients can't spoof time |
| D8 | SQLite concurrency | `timeout=5`, short-lived connections per call | Two processes share one DB |

## 11. Roadmap & Acceptance Tests

| M | Module | Acceptance test | Status |
|---|---|---|---|
| M0 | Roadmap + this file | User approves | ✅ approved |
| M1 | `database.py` | Tables created; insert/read events, alerts, incidents via quick script; data persists after restart | ✅ tested (22 checks pass) |
| M2 | `detector.py` + `tests/test_detection.py` | Tests pass for each rule: below threshold → no alert, at threshold → alert | ✅ tested (16 tests, plain python; pytest not run) |
| M3 | `server.py` | `nc`/test script sends JSON line → row in `events`; bad JSON ignored without crash; multiple clients handled (threads) | ❌ |
| M4 | `client.py` | Modes `normal`, `repeat`, `scan`, `spike` send expected events | ❌ |
| M5 | Server + detector integration | `scan` mode → alert + incident rows in DB | ❌ |
| M6 | Flask base + Dashboard | Cards show real counts; empty DB renders without error | ❌ |
| M7 | `/network`, `/alerts`, `/logs` | Tables match DB; filters work | ❌ |
| M8 | `/incidents` actions | Status change persists after refresh and app restart | ❌ |
| M9 | `/about` + CSS polish | Server state shown; responsive layout | ❌ |
| M10 | End-to-end test + README steps | Full workflow (Section 13) passes | ❌ |
| M11 | Demo plan + viva Q&A | Document complete | ❌ |

## 12. Setup (planned — unverified)

```bash
python -m venv venv
venv\Scripts\activate          # Windows   (Linux/Mac: source venv/bin/activate)
pip install -r requirements.txt   # flask (+ pytest)
```

Run (3 terminals):
```bash
python server.py
python app.py
python client.py scan          # or: normal | repeat | spike
```
Open http://127.0.0.1:5000

## 13. Expected Workflow (final demo)

1. Start server → 2. Start Flask → 3. Run clients → 4. Server logs events → 5. Alerts created → 6. Inspect dashboard → 7. Update incident status → 8. Refresh/restart → status persists.

## 14. Implemented & Tested Features

**M1 — `database.py` (✅ tested by `python tests/test_database.py`, 22 checks, run in sandbox)**
- `init_db()` repeatable; tables `events`, `incidents`, `alerts`; foreign keys ON; index on (source, timestamp)
- Writes: `add_event`, `add_incident`, `add_alert`, `update_incident_status` (severity/status validated → `ValueError`)
- Detector/server reads: `get_recent_events(source, seconds)`, `find_active_incident(source, title)`
- Page reads: `get_events(limit, event_type, severity)`, `get_alerts(limit)`, `get_incidents()`, `get_nodes(active_seconds)`, `get_counts()`
- Timestamps: UTC `YYYY-MM-DD HH:MM:SS` via `now_utc()`; window queries use SQLite `datetime('now', ...)`
- Alert "status" is not stored: it is its incident's status (JOIN in `get_alerts`)
- Parameterized SQL confirmed (injection-style source string stored as plain text)
- Active incident = `open` or `acknowledged`; once `contained`/`resolved`, a new match creates a NEW incident
- DB file `cybershield.db` sits next to `database.py`; create manually with `python database.py`

**M2 — `detector.py` (✅ 16 tests pass via `python tests/test_detection.py`, run in sandbox; `python -m pytest tests/` not yet verified, pytest not installed there)**
- Pure functions, no DB/sockets. `detect(recent_events)` → list of `{rule, severity, description}`
- Constants: `WINDOW_SECONDS=10`, `REPEATED_CONNECTION_THRESHOLD=5`, `PORT_SCAN_THRESHOLD=4`, `TRAFFIC_SPIKE_THRESHOLD=20`
- Rules use `>=`. Repeated connections counts `connection_attempt` events only; port scan counts DISTINCT `dest_port` among `port_probe` events only (so normal traffic to many ports can't trigger it); spike counts all events
- Severities: repeated=medium, port_scan=high, spike=medium
- Helpers: `event_severity(type)` (normal_traffic=info, connection_attempt=low, port_probe=low; unknown → `ValueError`), `incident_title(rule, source)`, `VALID_EVENT_TYPES`, `RULE_TITLES`

## 15. Planned / Unverified Features

Everything in Sections 5–8 except the database layer listed in Section 14.

## 16. Known Issues

- **Alert flooding (to solve in M5):** because rules use `>=`, every extra event past the threshold in the same window re-fires the rule (e.g. 25 spike events → several alerts). Plan: server skips adding an alert if the same rule already alerted on the active incident within the window (needs a small DB helper).
- pytest run not verified yet (plain-python runner works).

## 17. Decision D9

**D9 (added in M2):** port-scan rule counts only `port_probe` events, not every event with a port. Reason: avoids false positives from normal traffic.

## 17b. Conflicts Found Between Spec and Prior Decisions

No prior `PROJECT_MASTER.md` was supplied; this is the first version. Spec adopted as-is, with proposed choices in Section 10.

## 18. Change Log

| Date | Change |
|---|---|
| 2026-10-21 | Initial file created from spec; awaiting approval of M0 |
| 2026-10-21 | M0 approved (D1–D8). M1 `database.py` + `tests/test_database.py` added and tested |
| 2026-10-21 | M2 `detector.py` + `tests/test_detection.py` added; 16 tests pass; D9 and alert-flooding note recorded |