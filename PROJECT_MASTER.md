# PROJECT_MASTER.md — CyberShield

> Single source of truth across Claude chats. Read this FIRST in every new chat. Never assume a milestone is done unless it is marked ✅ here AND the code confirms it.

**Last updated:** 2026-10-28 (M5 complete)

**Current milestone:** M5 done ✅ → M6 next

**Next step:** M6 — Flask base + Dashboard: write `app.py` (route `/`, reads via `database.get_counts()`, `get_events()`, `get_alerts()`), `templates/base.html`, `templates/dashboard.html`, `static/css/style.css` (dark navy theme). Empty DB must render without error. Test with Flask's test client in `tests/test_app.py`.

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

 client.py (nodes)          server.py (TCP, port 9999)           app.py (Flask, port 5000)

 ┌──────────────┐  JSON\n   ┌────────────────────────┐          ┌─────────────────────┐

 │ node-1..N    │ ────────▶ │ accept → parse → store │          │ routes → templates  │
 │ normal/attack│   TCP     │        │               │          │ POST status updates │
 └──────────────┘           │        ▼               │          └──────────┬──────────┘
                            │   detector.py          │                     │
                            │   (3 rules)            │                     │
                            └───────────┬────────────┘                     │

                                        ▼                                  ▼

                                 ┌────────────────────────────────────────────┐

                                 │          SQLite  (cybershield.db)          │
                                 │      via database.py (shared by both)      │
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

Alert de-duplication (D10, implemented in M5): one active (open/acknowledged) incident per (source, rule); further matches attach to it; at most ONE alert per rule per incident per 10 s window.

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
│   ├── base.html
│   ├── dashboard.html
│   ├── network.html
│   ├── alerts.html
│   ├── incidents.html
│   ├── logs.html
│   └── about.html
├── static/
│   ├── css/style.css
│   └── js/main.js          # created ONLY if needed (currently not planned)
└── tests/
    ├── test_database.py    # added in M1 (plain-assert script)
    ├── test_detection.py
    ├── test_server.py      # added in M3 (plain-assert script)
    ├── test_client.py      # added in M4 (plain-assert script)
    └── test_integration.py # added in M5 (plain-assert script)

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
| M3 | `server.py` + `tests/test_server.py` | JSON-line validation and SQLite storage; malformed and oversized input rejected; multiple clients handled (threads) | ✅ tested (6 tests pass via plain Python) |
| M4 | `client.py` + `tests/test_client.py` | Modes `normal`, `repeat`, `scan`, `spike` send expected events | ✅ tested (6 tests pass via plain Python; end-to-end run with real server on port 9999 also checked) |
| M5 | Server + detector integration | `scan` mode → alert + incident rows in DB | ✅ tested (8 tests in `tests/test_integration.py`; all 5 test files pass) |
| M6 | Flask base + Dashboard | Cards show real counts; empty DB renders without error | ❌ |
| M7 | `/network`, `/alerts`, `/logs` | Tables match DB; filters work | ❌ |
| M8 | `/incidents` actions | Status change persists after refresh and app restart | ❌ |
| M9 | `/about` + CSS polish | Server state shown; responsive layout | ❌ |
| M10 | End-to-end test + README steps | Full workflow (Section 13) passes | ❌ |
| M11 | Demo plan + viva Q&A | Document complete | ❌ |

## 12. Setup (planned — unverified)

```bash

python -m venv venv

venv\Scripts\activate          # Windows   (Linux/Mac: source venv/bin/activate)

pip install -r requirements.txt   # flask (+ pytest)

```

Run (3 terminals):

```bash

python server.py

python app.py

python client.py scan          # or: normal | repeat | spike

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

**M3 — `server.py` + `tests/test_server.py` (✅ 6 tests pass via `python tests/test_server.py`, verified locally on 2026-10-21)**
- Threaded TCP server listens on `127.0.0.1:9999` and accepts newline-delimited JSON.
- Validates JSON object structure, `source`, `event_type`, optional `dest_port`, and `message`.
- Stores valid events in SQLite using `database.add_event()`; severity is assigned with `detector.event_severity()`.
- Rejects malformed JSON, invalid fields, and oversized lines without stopping the server.
- Supports multiple events per connection and concurrent clients.
- SQL-injection-style input is stored as plain text.
- (M3 note, now superseded) Detection was added in M5, see below.

**M5 — detection wired into `server.py` (✅ 8 tests pass via `python tests/test_integration.py`: real client → TCP server → detector → SQLite)**
- `process_event()` stores the event, loads `database.get_recent_events(source, WINDOW_SECONDS)`, runs `detector.detect()`, then per alert: reuse the active incident for (source, rule title) or create a new `open` incident, then add the alert (linked to the triggering event)
- Alert flooding fixed: new `database.has_recent_alert(incident_id, rule, seconds)`; alert skipped if that incident already alerted for the rule within the window → `repeat` (6 events), `scan` (5), `spike` (25) each give exactly 1 alert + 1 incident
- `normal` traffic and unrelated sources create no alerts; sources are independent
- Acknowledged incident is reused (no new incident); resolved/contained incident → next match creates a NEW incident
- Server prints `[ALERT] rule from source -> incident #N: description` to its console
- `tests/test_database.py` gained 2 checks for `has_recent_alert` (now 24 checks)
- Known limit: two threads handling the SAME source at exactly the same moment could both pass the de-dup check (not expected in the demo; single client per source)

**M4 — `client.py` + `tests/test_client.py` (✅ 6 tests pass via `python tests/test_client.py`; also run end-to-end against a real `server.py` on port 9999, 2026-10-28)**
- Usage: `python client.py <normal|repeat|scan|spike|all> [--source NAME]`; sends to 127.0.0.1:9999 only, one TCP connection per scenario, one JSON line per event
- Scenarios (default source → events): `normal` node-1 → 5 `normal_traffic` (0.5 s apart); `repeat` node-2 → 6 `connection_attempt` to port 22 (0.2 s); `scan` node-3 → 5 `port_probe` to ports 21,22,23,80,443 (0.2 s); `spike` node-4 → 25 `normal_traffic` (0.05 s); `all` runs the four in order
- Verified with the detector: normal → no alert; repeat → `repeated_connections`; scan → `port_scan`; spike → `traffic_spike` (each exactly one rule)
- Server not running → friendly message and exit code 1 (no traceback)
- `send_scenario(mode, source, host, port, delay)` is importable (tests use it with `delay=0`)
## 15. Planned / Unverified Features

M6–M11 remain planned/unverified (Flask app, templates, CSS are still empty files).

## 16. Known Issues

- Alert flooding: ✅ fixed in M5 (see Section 14).

- pytest run not verified yet (plain-python runner works).

## 17. Decision D9

**D9 (added in M2):** port-scan rule counts only `port_probe` events, not every event with a port. Reason: avoids false positives from normal traffic.

## 17a. Decision D10

**D10 (added in M5):** alert de-duplication = one alert per (incident, rule) per `WINDOW_SECONDS`; incident reuse only while status is `open`/`acknowledged`.

## 17b. Conflicts Found Between Spec and Prior Decisions

No prior `PROJECT_MASTER.md` was supplied; this is the first version. Spec adopted as-is, with proposed choices in Section 10.

## 18. Change Log

| Date | Change |
|---|---|
| 2026-10-21 | Initial file created from spec; awaiting approval of M0 |
| 2026-10-21 | M0 approved (D1–D8). M1 `database.py` + `tests/test_database.py` added and tested |
| 2026-10-21 | M2 `detector.py` + `tests/test_detection.py` added; 16 tests pass; D9 and alert-flooding note recorded |
| 2026-10-21 | M3 `server.py` + `tests/test_server.py` added; 6 tests pass; JSON-line validation and event storage verified; M4 next |
| 2026-10-28 | M4 `client.py` + `tests/test_client.py` added; 6 tests pass; end-to-end with real server checked; blank lines that broke markdown tables repaired; M5 next |
| 2026-10-28 | M5 detection wired into `server.py`; `database.has_recent_alert()` added; flood fix; `tests/test_integration.py` (8 tests) added; M6 next |