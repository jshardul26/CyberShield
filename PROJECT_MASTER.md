# PROJECT_MASTER.md — CyberShield

> Single source of truth across Claude chats. Read this FIRST in every new chat. Never assume a milestone is done unless it is marked ✅ here AND the code confirms it.

**Last updated:** 2026-10-29 (M10 complete)

**Current milestone:** M10 done ✅ → M11 next

**Next step:** M11 — write `DEMO_AND_VIVA.md` (the final document; Markdown, in the repo root). Contents: (1) a timed demo script of about 5-7 minutes that follows README "Demo walkthrough" with the exact commands, the clicks, and what the audience should see at each step (expected numbers: `python client.py all` → 41 events, 3 alerts, 3 open incidents, 4 nodes on a fresh database); (2) a short "what each file does" table mapped to the four mandatory requirements (sockets, database, web, cybersecurity); (3) 20-30 viva questions with short answers that are TRUE for this code (check each answer against the source before writing it): why TCP, why newline-delimited JSON, why threads, how oversized/malformed input is handled, why parameterized SQL, how the 10 s window and the thresholds work, how alert de-duplication and incident reuse work (D10), why status only moves forward (D13), why two processes share SQLite (D8), why `Run simulation` uses fixed arguments (D4), what the About reachability check does, what the known limits are (Section 16), what could be improved next; (4) a "if something goes wrong during the demo" checklist (server not running, port in use, empty dashboard, delete `cybershield.db`). Do not invent features: anything not in the code goes under "future work". After writing it, check every command and number in it against a real run.

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
├── README.md
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
    ├── test_integration.py # added in M5 (plain-assert script)
    ├── test_app.py         # added in M6 (Flask test client, plain-assert script)
    └── test_end_to_end.py  # added in M10 (full demo workflow, plain-assert script)

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
| M6 | Flask base + Dashboard | Cards show real counts; empty DB renders without error | ✅ tested (5 tests in `tests/test_app.py`; live run with server + client + app checked) |
| M7 | `/network`, `/alerts`, `/logs` | Tables match DB; filters work | ✅ tested (15 tests in `tests/test_app.py`, 51 across the suite incl. pytest; live run with real server + simulation checked) |
| M8 | `/incidents` actions | Status change persists after refresh and app restart | ✅ tested (7 new tests in `tests/test_app.py`, 22 there, 58 across the suite under pytest; live run: statuses changed, app restarted, statuses still saved) |
| M9 | `/about` + CSS polish | Server state shown; responsive layout | ✅ tested (7 new app tests, 1 new detector test; 66 across the suite under pytest; live run checked server up/down; all pages screenshotted in headless Chromium at 1280 px and 375 px, no sideways page scroll) |
| M10 | End-to-end test + README steps | Full workflow (Section 13) passes | ✅ tested (`tests/test_end_to_end.py`; 67 tests across the suite under pytest; README steps run literally in a clean venv on a fresh clone) |
| M11 | Demo plan + viva Q&A | Document complete | ❌ |

## 12. Setup (✅ verified on Linux in a clean venv on 2026-10-29; Windows commands unverified)

Full, user-facing version: `README.md`. Summary:

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
**M6 — Flask base + Dashboard (✅ 5 tests pass via `python tests/test_app.py`; live run: `python server.py` + `python app.py` + `python client.py all`, then `GET /` → HTTP 200 with 41 events, 3 alerts, 3 open incidents, 4 nodes)**
- `app.py`: Flask app on 127.0.0.1:5000 (`debug=False`); `python app.py` calls `database.init_db()` first; route `/` (`dashboard`); context processor builds the nav from existing endpoints
- `templates/base.html` (layout, nav, footer, `head_extra` block), `templates/dashboard.html` (4 summary cards, latest 5 alerts, latest 10 events, severity/status badges, friendly empty states), `static/css/style.css` (dark navy theme, responsive grid, tables scroll inside a wrapper)
- Jinja auto-escaping verified: a source named `<script>alert(1)</script>` is rendered as text
- `requirements.txt` now contains `Flask>=3.0` (tested with Flask 3.1.3)
- Dashboard reads only real DB data; empty DB renders without error

**M7 — `/network`, `/alerts`, `/logs` (✅ 15 tests pass in `tests/test_app.py`; full suite 51 tests pass under pytest; live run: real `server.py` + `app.py`, POST simulate → 3 alerts, 4 Active nodes)**
- `/network`: nodes table from `get_nodes()` (Active/Idle badge, last seen, event count), "Run simulation" button, latest 15 events, friendly empty states
- `POST /network/simulate`: runs `[sys.executable, client.py, "all"]` via `subprocess.run` with a fixed argument list, no shell, 30 s timeout; NOTHING from the request is used (D4). It redirects to `/network?sim=<key>`; the key is looked up in the fixed `SIM_MESSAGES` dict, so unknown values show nothing. Client exit code 0 → ok, 1 → server unreachable, anything else / timeout / OSError → failed. GET returns 405
- `/alerts`: `get_alerts(100)` with rule, details, severity, status (= its incident's status) and an incident link (a plain `#N` until `/incidents` exists). All alerts are suspicious; normal traffic stays an `info` event on `/logs` (D12)
- `/logs`: `get_events(100, event_type, severity)` with GET filters. Values not in `detector.VALID_EVENT_TYPES` / `database.SEVERITIES` are dropped and a notice is shown (D12); dropdowns keep the selected value; "No events match this filter" empty state
- `style.css`: node badges, buttons, filter form, select, notice box
- Tests use fresh temporary databases (`EmptyDatabase` helper for empty-state checks) and a `FakeRun` stand-in so no real client starts during tests

**M8 — `/incidents` + status changes (✅ 22 tests in `tests/test_app.py`; full suite 58 tests pass under pytest; live run: real `server.py` + `app.py` + `client.py all` → 3 incidents; acknowledge/contain/resolve via POST, app restarted, statuses persisted; backward move → 400, unknown id → 404)**
- `database.get_incident(id)` added (row or `None`); 2 new checks in `tests/test_database.py` (now 26 checks)
- `/incidents`: table from `get_incidents()` (ID, created, source, title, severity, alert count linking to `/alerts`, status badge). Each row has `id="incident-<id>"`, which `/alerts` links to; CSS highlights the targeted row (`tr:target`)
- `POST /incidents/<int:incident_id>/status` (form field `status`): unknown id → 404; a status that is not an allowed next step → 400 (nothing written); success → redirect to `/incidents#incident-<id>`. GET → 405
- Allowed moves (D13), kept in `NEXT_STATUSES` in `app.py`: `open → acknowledged | contained | resolved`, `acknowledged → contained | resolved`, `contained → resolved`, `resolved → (none, shows "Closed")`. The page shows only the buttons the server would accept
- Acknowledged incidents stay "active" (dashboard card still counts them; the server still reuses them for new alerts); contained/resolved ones leave the open count and a new match creates a new incident (existing M1/M5 behaviour, unchanged)
- Alert pages show the incident's current status automatically (status is joined from `incidents`)
- Jinja escaping verified for incident title/source

**M9 — `/about` + CSS polish (✅ 29 tests in `tests/test_app.py`; 66 across the suite under pytest; live run: server up → "Reachable", server stopped → "Not reachable"; visual check in headless Chromium)**
- `/about` (`about.html`): monitoring-server status badge, "Simulation only" statement (includes "does not detect all real-world attacks"), architecture flow (client.py → server.py + detector.py → SQLite → app.py) with the 4 data-flow steps, and the detection rules table
- Reachability: `server_reachable()` in `app.py` opens a TCP connection to `server.HOST:server.PORT` (timeout 1 s) and closes it at once. Sends nothing, so no event is stored (tested). The address comes only from `server.py` constants; query parameters are ignored (tested)
- The rules table is built by `detection_rules()` from the CURRENT `detector.py` constants (tested by changing a threshold at runtime), and severities now come from the new `detector.RULE_SEVERITY` dict, which `detect()` also uses (single source of truth; 1 new test in `tests/test_detection.py`, now 17)
- CSS polish, found by looking at real screenshots: (1) action buttons in `/incidents` were clipped on desktop → `td.actions` wraps; (2) long Details/Message/Title cells wrap (`td.wrap`); (3) on phones (≤600 px) every table turns into one card per row using `data-label` attributes (D14), so Status and Actions are never hidden off-screen; (4) architecture boxes stack with ↓ arrows on phones; (5) visible keyboard focus outline; filter inputs fill the width on phones
- Checked with `python3 -I` Playwright script (not part of the repo): all 6 pages at 1280 px and 375 px → 0 px horizontal overflow, 0 console errors

**M10 — end-to-end test + README (✅ `tests/test_end_to_end.py` passes; 67 tests across the suite under pytest; README steps run literally in a clean venv on a fresh clone)**
- `tests/test_end_to_end.py::test_full_demo_workflow`: temporary DB, a real `server.Server` on a free port in a thread, and the real client scenarios. It checks, in order: server reachable (About) and empty dashboard → traffic from the 4 scenarios gives exactly 41 events, 3 alerts (one per attack, none for normal traffic), 3 open incidents, 4 nodes → every page shows the real data (dashboard cards, network, alerts, logs filters, incidents, about) → acknowledge / contain / resolve through the web routes → "restart" (TCP server stopped: About says Not reachable; new server and new web client on the same DB file) → statuses persisted → the same attacks again: node-3's acknowledged incident is reused (no new incident) and node-2's contained incident gets a NEW incident (D10), the old one stays contained
- Robust under pytest: it sets and restores `database.DB_PATH` / `server.PORT` inside the test (other test files set the DB path at import time). Stable over repeated runs. Sabotage check: with the port-scan threshold raised so the rule cannot fire, the test fails ("timed out waiting for: 3 alerts")
- `README.md`: what it is, how it works, rule table, requirements, setup (Linux/macOS and Windows), 3-terminal run, client modes, demo walkthrough, pages, tests, project structure, troubleshooting
- README verification (fresh `git clone` into an empty directory, `python3 -m venv venv`, Python 3.13.18): `pip install -r requirements.txt` → Flask 3.1.3; `python -m pytest tests/ -q` → 67 passed (after the optional `pip install pytest`); `python tests/test_end_to_end.py` passes; every `tests/test_*.py` exits 0 alone; no `cybershield.db` left by the tests; `python client.py scan` with no server → friendly message, exit 1; `python server.py` + `python app.py` → `cybershield.db` auto-created, About says Reachable; `python client.py scan --source lab-pc` and `python client.py all` send 5 and 41 events; all 6 pages return 200; POST `/network/simulate` → redirect to `?sim=ok`; an acknowledged incident was still acknowledged after stopping and restarting both programs
- Not run: the Windows commands (`venv\Scripts\activate`) and macOS; they are standard but unverified

## 15. Planned / Unverified Features

M11 (demo plan + viva Q&A document) remains planned. README Windows/macOS commands are unverified. No empty placeholder files are left. The visual layout was checked in headless Chromium by Claude on 2026-10-29 (desktop and phone width), but NOT in Safari/Firefox or on a real phone: please open http://127.0.0.1:5000 in your own browser and report anything odd.

## 16. Known Issues

- Alert flooding: ✅ fixed in M5 (see Section 14).

- pytest run: ✅ verified 2026-10-29 (`python -m pytest tests/` → 67 passed; Flask 3.1.3, pytest 9.1.1, Python 3.13).

- No CSRF tokens on the POST forms (simulate, incident status). Accepted for a localhost-only classroom demo (extra libraries are not allowed, see Section 3); do not expose the app beyond 127.0.0.1.

- Two operators changing the same incident at the same moment: the last valid request wins (check-then-update is not atomic). Not expected in a single-user demo.

- The "Run simulation" request blocks for about 6 s while the client runs (acceptable for a local demo; Flask's dev server is threaded so other pages still load).

## 17. Decision D9

**D9 (added in M2):** port-scan rule counts only `port_probe` events, not every event with a port. Reason: avoids false positives from normal traffic.

## 17a. Decision D10

**D10 (added in M5):** alert de-duplication = one alert per (incident, rule) per `WINDOW_SECONDS`; incident reuse only while status is `open`/`acknowledged`.

## 17a-2. Decision D11

**D11 (added in M6):** the dashboard auto-refreshes every 5 s using a plain `<meta http-equiv="refresh">` tag (no JavaScript, still "normal page refresh"). Other pages do not auto-refresh (the incidents page has action buttons). Nav links are shown only for pages whose Flask endpoint exists (`NAV` list in `app.py`).

## 17a-3. Decision D12

**D12 (added in M7):** (a) `/logs` ignores invalid filter values and shows a notice instead of returning an error; the bad value is never used in SQL or echoed. (b) On `/alerts`, "info vs suspicious" is shown by explanation: every alert is suspicious, while normal traffic is an `info` event visible only on `/logs`. (c) The simulation outcome is passed to `/network` as `?sim=ok|down|failed` (fixed keys, no flash/session needed).

## 17a-4. Decision D13

**D13 (added in M8):** incident status can only move forward (`open → acknowledged → contained → resolved`, skipping ahead is allowed, going back is not). It is enforced on the server (`NEXT_STATUSES` in `app.py`), not only by hiding buttons. Reason: matches the real handling flow and keeps the de-duplication rule (D10) simple, since a resolved incident is never reopened; a new match creates a new incident instead.

## 17a-5. Decision D14

**D14 (added in M9):** on screens ≤600 px every data table is shown as one card per row (pure CSS: `table.stack` + `data-label` on each `<td>`, no JavaScript). Reason: horizontal scrolling hid the Status and Actions columns on phones. When adding a new table, give it `class="stack"` and a `data-label` on every cell (a test checks that every cell has one).

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
| 2026-10-28 | M6 `app.py`, `base.html`, `dashboard.html`, `style.css`, `requirements.txt`, `tests/test_app.py` added; 5 tests pass; D11 recorded; M7 next |
| 2026-10-29 | M7 `/network` (+ POST `/network/simulate`), `/alerts`, `/logs` added with templates and CSS; 10 new tests (15 in `test_app.py`, 51 total under pytest); pytest verified; D12 recorded; M8 next |
| 2026-10-29 | M8 `/incidents` + POST status route, `database.get_incident()`, `incidents.html`, button/`:target` CSS; 7 new app tests + 2 database checks (58 total under pytest); restart persistence verified live; D13 recorded; M9 next |
| 2026-10-29 | M9 `/about` page, `server_reachable()`, `detection_rules()`, `detector.RULE_SEVERITY`, `about.html`; CSS polish from real screenshots (clipped buttons, wrapping cells, phone card tables, stacked flow boxes, focus outline); 8 new tests (66 total under pytest); D14 recorded; M10 next |
| 2026-10-29 | M10 `tests/test_end_to_end.py` (full demo workflow incl. restart and incident reuse), `README.md`; README steps verified in a clean venv on a fresh clone; 67 tests under pytest; M11 next |