# CyberShield: Demo Script and Viva Q&A

A simulated network monitoring project: client programs send events over **TCP** to a server, which applies three detection rules, stores everything in **SQLite**, and shows it on a **Flask** dashboard.

Everything here was checked against the code and a real run on 2026-10-29 (Linux, Python 3.13, Flask 3.1.3). Anything not in the code is listed under "Future work", not claimed.

---

## 1. Demo script (about 7 minutes)

### Before you start (2 minutes, off stage)

1. Open **three terminals** in the project folder, each with the virtual environment activated (`source venv/bin/activate`, or `venv\Scripts\activate` on Windows).
2. Start from a clean slate: make sure `cybershield.db` does not exist in the project folder. If it does, stop `server.py` and `app.py` first, then delete it.
3. Open a browser window, but do not load a page yet.

### Timed walkthrough

| Time | You do | The audience should see |
|---|---|---|
| 0:00 | Say what it is: "Simulated clients send events over TCP to a monitoring server. The server stores them in SQLite and applies three rules. A Flask dashboard shows the result. It is a simulation: everything stays on 127.0.0.1." | Nothing yet. |
| 0:45 | **Terminal 1:** `python server.py` | `CyberShield server listening on 127.0.0.1:9999  (Ctrl+C to stop)` |
| 1:00 | **Terminal 2:** `python app.py` | Flask start-up messages (the dashboard is on port 5000). |
| 1:15 | **Browser:** open `http://127.0.0.1:5000/about` | A **Reachable** badge for `127.0.0.1:9999`, the "Simulation only" text, the architecture flow, and the three-rule table. |
| 1:45 | Click **Dashboard** | Four cards all showing **0**, plus the messages "No alerts yet" and "No events yet". |
| 2:00 | **Terminal 3:** `python client.py all` (takes about 6 seconds) | Terminal 3 prints `normal: sent 5 events`, `repeat: sent 6 events`, `scan: sent 5 events`, `spike: sent 25 events`. Terminal 1 prints a `stored event` line per event and exactly three `[ALERT]` lines (below). |
| 2:30 | Watch the dashboard (it refreshes itself every 5 seconds) | Cards change to **41** events, **3** alerts, **3** open incidents, **4** nodes. |
| 3:15 | Click **Network** | Four nodes, all **Active**: node-1 (5 events), node-2 (6), node-3 (5), node-4 (25). |
| 3:30 | Click **Alerts** | Three alerts: `repeated_connections` (medium, node-2), `port_scan` (high, node-3), `traffic_spike` (medium, node-4). Point out that normal traffic raised none. |
| 3:50 | Click **Logs**, choose type `port_probe` | **5** events. Then type `normal_traffic`: **30** events (node-1's 5 plus node-4's 25). Severity `low`: **11** events. Severity `high`: "No events match this filter" (events are only `info` or `low`; `medium` and `high` belong to alerts). |
| 4:15 | Click **Incidents** | Three incidents, all **open**. #1 node-2, #2 node-3, #3 node-4 (newest is listed first). |
| 4:30 | Press **Acknowledge** on #2, **Contain** on #1, **Resolve** on #3 | Each badge changes. #3 now shows **Closed** instead of buttons. Open the Dashboard: **Open incidents = 1** (acknowledged still counts as active). |
| 5:15 | Say: "Status only moves forward. The server enforces that, not just the buttons." | (Optional) Mention that a backward request gets HTTP 400. |
| 5:30 | **Persistence:** press Ctrl+C in terminals 1 and 2, then start `python server.py` and `python app.py` again. Reload **Incidents**. | Statuses are still resolved, acknowledged, contained. The data lives in `cybershield.db`, not in memory. |
| 6:15 | **Bonus (optional, 1 minute):** `python client.py scan`, then `python client.py repeat` | Totals become **52 events, 5 alerts, 4 incidents**. node-3's acknowledged incident #2 is **reused** (now 2 alerts, no new incident). node-2's contained incident #1 is not reused: a **new incident #4** opens. Dashboard Open incidents = **2**. |

The three alert lines in terminal 1 look like this:

```
[ALERT] repeated_connections from node-2 -> incident #1: 5 connection attempts in 10 s (threshold 5)
[ALERT] port_scan from node-3 -> incident #2: 4 different ports probed in 10 s (threshold 4)
[ALERT] traffic_spike from node-4 -> incident #3: 20 events in 10 s (threshold 20)
```

You can press **Run simulation** on the Network page instead of using terminal 3. The page waits about 6 seconds, then shows a "Simulation finished" message.

---

## 2. What each file does

| File | Role | Mandatory requirement |
|---|---|---|
| `server.py` | Threaded TCP server on port 9999. Validates each JSON line, stores the event, runs the detector, records alerts and incidents. | **Sockets** |
| `client.py` | Simulated nodes. Sends one JSON line per event over TCP to 127.0.0.1:9999. Modes: `normal`, `repeat`, `scan`, `spike`, `all`. | **Sockets** |
| `database.py` | SQLite layer: three tables (`events`, `alerts`, `incidents`) and all queries. Shared by the server and the web app. | **Database** |
| `app.py` | Flask app on port 5000 with six pages and two POST actions (incident status, run simulation). | **Web** |
| `templates/`, `static/css/style.css` | Jinja HTML pages and the responsive dark theme. No JavaScript at all. | **Web** |
| `detector.py` | Three threshold rules as pure functions, plus the severity tables. | **Cybersecurity** |
| Incident workflow (`app.py`, `database.py`) | Alerts group into incidents that an operator moves open → acknowledged → contained → resolved. | **Cybersecurity** |
| `tests/` | 66 pytest tests (plus a 26-check script for the database layer) including a full end-to-end demo test. | Quality |
| `PROJECT_MASTER.md`, `README.md` | Design decisions, status, setup and run instructions. | Documentation |

---

## 3. Viva questions and answers

### Sockets and networking

**1. Why TCP and not UDP?**
TCP is reliable and ordered: every event arrives once and in order. The detector counts events, so a lost or reordered packet would change the result. UDP would need that handling written by hand.

**2. Why newline-delimited JSON?**
TCP is a byte stream with no message boundaries, so the receiver needs a way to know where one message ends. One JSON object per line, ended by `\n`, is simple and human-readable. `json.dumps` escapes any newline inside values, so a line is always one complete message.

**3. Why threads?**
`server.py` uses `ThreadingTCPServer`: each connection gets its own thread. Several clients can send at the same time and one slow or silent client cannot block the others. Threads are also marked as daemon threads so they do not keep the program alive on exit.

**4. What happens with malformed input?**
The line is rejected with a printed reason (for example `rejected: not valid JSON`), nothing is stored, and the connection stays open for the next line. The validation checks: it is a JSON object, `source` is a non-empty string of at most 50 characters, `event_type` is one of the three valid types, `dest_port` is missing or an integer from 0 to 65535 (booleans are refused), and `message` is a string (cut to 200 characters).

**5. What happens with oversized input?**
A line longer than 4096 bytes makes the server print `line too long, dropping connection` and close that connection. A live check confirmed the client sees the connection closed. The server keeps running. A client that stays silent for 30 seconds is also dropped.

**6. Why do you set `allow_reuse_address`?**
So that after stopping and restarting `server.py` the port 9999 can be bound again immediately instead of waiting for old connections in the TCP TIME_WAIT state.

**7. Why 127.0.0.1 only?**
The project is a simulation. Binding to the loopback address means nothing outside the machine can connect, and nothing real is scanned or attacked.

**8. Can a client lie about who it is?**
Yes. The `source` name is whatever the client writes, with no authentication. Only the **timestamp** is trusted, because the server generates it (decision D7) and clients cannot backdate events. Client authentication is future work.

### Database

**9. Why SQLite?**
It is in Python's standard library, needs no database server, and stores everything in one file (`cybershield.db`), which fits a local demo. MySQL was not allowed by the project constraints.

**10. What is the schema?**
Three tables. `events` (what was received), `incidents` (a title, source, severity, status), and `alerts` (a rule that fired, linked to its triggering event and its incident). One incident has many alerts; one alert points to one event. Foreign keys are switched on, and there is an index on `events(source, timestamp)` for the window query.

**11. Why parameterized SQL?**
Values are passed separately from the SQL text (`?` placeholders), so input is never interpreted as SQL. A test stores an injection-style source string and confirms it is saved as plain text. Where a query is built dynamically (the log filters), only fixed SQL fragments are joined; the values still go through placeholders, and the web layer also drops filter values that are not in the allowed lists.

**12. How can two processes share one SQLite file?**
Each function opens a short-lived connection with a 5-second timeout (decision D8) and closes it. SQLite locks the file during a write, and the timeout makes a second writer wait instead of failing. There is no long-lived global connection.

**13. Why is an alert's status not stored in the alerts table?**
It is the status of its incident. `get_alerts` reads it with a JOIN, so changing the incident updates how every one of its alerts is displayed, with no duplicate data to keep in sync.

**14. How is a node "Active"?**
A node is a distinct `source` in the events table. It is **Active** if its latest event is within the last 60 seconds, otherwise **Idle** (decision D2). There is no separate nodes table.

### Detection and cybersecurity

**15. How do the rules work?**
On every stored event, the server loads that source's events from the last 10 seconds (including the new one) and passes them to `detect()`, a pure function with no database or sockets. Rules use `>=`:

| Rule | Counts | Threshold | Severity |
|---|---|---|---|
| Repeated connections | `connection_attempt` events | 5 | medium |
| Port-scan-like | distinct `dest_port` values among `port_probe` events only | 4 | high |
| Traffic spike | events of any type | 20 | medium |

The thresholds are constants at the top of `detector.py`.

**16. Why does the port-scan rule only count `port_probe` events?**
So that normal traffic to many ports (web, DNS, and so on) cannot trigger a false port-scan alert (decision D9).

**17. Why a 10-second window queried from the database?**
The server stays stateless: no in-memory counters to lose or get out of sync, and it is easy to explain and test (decision D3).

**18. How does alert de-duplication work?**
The server looks for an **active** incident (open or acknowledged) for the same source and rule title and reuses it, otherwise it creates a new one. Then it skips the alert if that incident already received an alert for the same rule in the last 10 seconds (decision D10). One attack therefore gives one alert and one incident instead of a flood. If the activity continues beyond the window, another alert is added to the same incident; This was observed when the simulation was run twice (6 alerts, still 3 incidents).

**19. What happens when the same activity returns after an incident is closed?**
Once an incident is **contained** or **resolved** it is no longer active, so a new match creates a **new** incident. The old one is left as it was.

**20. Why can an incident only move forward?**
The order is open → acknowledged → contained → resolved; skipping ahead is allowed, going back is not (decision D13). It mirrors real incident handling and keeps de-duplication simple, because a resolved incident is never reopened. The rule is enforced in `app.py` (`NEXT_STATUSES`): a backward or invalid status returns HTTP 400 and writes nothing, and an unknown incident id returns 404. The buttons hide for the same reason, but hiding is not what protects it.

**21. What security measures does the web app have?**
Jinja auto-escaping (a source named `<script>alert(1)</script>` is shown as text), parameterized SQL, whitelisted filter values, POST-only state changes (GET returns 405), and the server only listens on 127.0.0.1.

**22. Why does "Run simulation" use fixed arguments?**
The button runs `client.py all` with a fixed argument list through `subprocess.run`, with no shell and a 30-second timeout. Nothing from the request is used in the command (decision D4), so there is no way to inject a command through the web page. The result message comes from a fixed dictionary keyed by `?sim=ok|down|failed`.

**23. What does the About page's reachability check do?**
When the page loads, `app.py` opens a TCP connection to `127.0.0.1:9999` with a 1-second timeout and closes it immediately. It sends nothing, so no event is stored. If the connection is accepted, the badge says **Reachable**, otherwise **Not reachable**. The address comes only from constants in `server.py`, never from the request.

### Web

**24. How does the page update without JavaScript?**
Only the dashboard refreshes itself, using a `<meta http-equiv="refresh" content="5">` tag (decision D11). The other pages update on a normal reload; the incidents page deliberately does not auto-refresh because it has action buttons. WebSockets and JavaScript frameworks were outside the constraints.

**25. How does it work on a phone?**
On screens up to 600 px wide, each table turns into one card per row (pure CSS, using a `data-label` on every cell, decision D14), so Status and Actions are never hidden off-screen. This was checked in headless Chromium only, not on a real phone or in other browsers.

### Testing, limits and future work

**26. How is it tested?**
66 pytest tests across the detector, server, client, integration and Flask app, plus a 26-check script for the database. The end-to-end test starts a real server on a free port, runs the real client scenarios, checks every page, changes statuses, "restarts" the server and web client, and confirms persistence and incident reuse. Tests use temporary databases, so your real `cybershield.db` is never touched.

**27. What are the known limits?**
- The rules are simple thresholds, per source. They cannot see a distributed or slow scan and do not detect all real-world attacks.
- No client authentication and no encryption (plain TCP).
- No CSRF tokens on the POST forms. Acceptable only because it is localhost-only; do not expose the app beyond 127.0.0.1.
- Two operators changing the same incident at the same moment: the last valid request wins.
- Two threads handling the *same* source at exactly the same moment could both pass the de-duplication check.
- "Run simulation" blocks the request for about 6 seconds (other pages still load).
- Deleting `cybershield.db` while the programs run breaks them (see section 4).
- Windows and macOS commands and Firefox/Safari layout are not verified.

**28. What could be improved next? (Future work, not implemented)**
CSRF tokens; an atomic status update (`UPDATE ... WHERE status = ?`); running the simulation in the background; client authentication and TLS; more rules (for example failed-login patterns or per-port rates); pagination on long tables; live updates on more pages.

---

## 4. If something goes wrong during the demo

| What you see | Likely cause | Fix |
|---|---|---|
| `client.py` prints "Cannot reach the server at 127.0.0.1:9999 ... Start it first" | `server.py` is not running | Start `python server.py`, then run the client again. |
| About page says **Not reachable**, or Run simulation shows "Could not reach the server" | Same: server not running | Start `python server.py`. |
| `server.py` fails with `OSError: [Errno 98] Address already in use` | An old copy still holds port 9999 (Windows shows a different error number) | Close the old copy, or end that process. |
| `app.py` prints "Port 5000 is in use by another program" | An old copy of the app (or another program) uses port 5000 | Close the old copy. |
| Dashboard still shows zeros after the client ran | Wait up to 5 s for the refresh. If still zero, check terminal 1 for `stored event` lines. If there are none, the server may be running from a different copy of the project folder. | Reload; run everything from the same folder. |
| Numbers are bigger than 41 / 3 / 3 / 4 | Old data is in the database (running `all` twice gives 82 events and 6 alerts but still 3 incidents) | Press Ctrl+C in terminals 1 and 2, delete `cybershield.db`, start both again. |
| Rerunning a scenario quickly adds events but no new alert | De-duplication: one alert per rule per incident per 10 s | Normal behaviour. Wait over 10 s to see another alert. |
| Dashboard shows a 500 error and terminal 1 shows `no such table: events` | `cybershield.db` was deleted while the programs were running | Stop both programs, then start them again (the tables are recreated on start-up). |
| No incident buttons on a row | The incident is resolved ("Closed"), or the buttons only offer later steps | Normal behaviour. |
| Nodes show **Idle** | More than 60 s since their last event | Normal. Run the client again. |
| `No module named flask` | The virtual environment is not activated | Activate it and run `pip install -r requirements.txt`. |

**Reset recipe:** Ctrl+C in terminal 1 and terminal 2 → delete `cybershield.db` in the project folder → `python server.py` and `python app.py` again.