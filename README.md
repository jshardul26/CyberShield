# CyberShield

A small **Computer Networks** project: simulated clients send normal and suspicious event messages over
**TCP** to a monitoring server. The server applies three simple detection rules, stores everything in
**SQLite**, and a **Flask** dashboard lets an operator inspect activity and handle incidents.

> **Simulation only.** All traffic stays on `127.0.0.1`. Nothing is scanned, attacked or blocked on a real
> network, and the three rules are deliberately simple: CyberShield does **not** detect all real-world attacks.

## How it works

```
client.py (nodes) --TCP, one JSON line per event--> server.py + detector.py --> SQLite (cybershield.db)
                                                                                      ^
                                                                    app.py (Flask dashboard, port 5000)
```

1. A client sends events (`normal_traffic`, `connection_attempt`, `port_probe`) to the server on port 9999.
2. The server validates each message, stores the event and runs the rules on that source's last 10 seconds.
3. A matching rule stores an alert and opens (or reuses) an incident for that source and rule.
4. You inspect alerts and logs in the browser and move incidents forward: acknowledged, contained, resolved.

| Rule | Triggers when (within 10 s, one source) | Severity |
|---|---|---|
| Repeated connection attempts | 5 or more `connection_attempt` events | medium |
| Port-scan-like activity | 4 or more different ports in `port_probe` events | high |
| Traffic spike | 20 or more events of any type | medium |

The thresholds are constants at the top of `detector.py`.

## Requirements

- Python 3 (developed and tested with Python 3.13)
- Flask 3 (installed from `requirements.txt`; tested with Flask 3.1.3)
- `pytest` is optional and only needed for `python -m pytest`

No other libraries, no database server, no internet connection needed after installing Flask.

## Setup

**Linux / macOS**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows**

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Use the same terminal window (with the virtual environment activated) for the commands below.
On Linux/macOS use `python3` if `python` is not found outside the virtual environment.

## Run the demo (3 terminals, each inside the project folder with the venv activated)

```bash
# terminal 1: the TCP monitoring server (port 9999)
python server.py

# terminal 2: the web dashboard (port 5000)
python app.py

# terminal 3: simulated clients
python client.py scan
```

Then open **http://127.0.0.1:5000**.

Client modes: `normal`, `repeat`, `scan`, `spike`, or `all` (runs the four in order, about 6 seconds).
Optional: `--source NAME` to choose the node name, for example `python client.py scan --source lab-pc`.

You can also press **Run simulation** on the Network page instead of using terminal 3 (the server must be running).

### Demo walkthrough

1. Start the server and the dashboard. The About page shows **Reachable** when the server is up.
2. Run `python client.py all` (or press **Run simulation**).
3. Dashboard: the cards show events, alerts, open incidents and nodes; it refreshes every 5 seconds.
4. Alerts page: one alert per attack (`repeated_connections`, `port_scan`, `traffic_spike`). Normal traffic raises none.
5. Logs page: filter events by type and severity.
6. Incidents page: press **Acknowledge**, **Contain** or **Resolve**. An incident only moves forward.
7. Stop and restart `server.py` and `app.py`, then reload Incidents: the statuses are still there.

## Pages

| Page | What it shows |
|---|---|
| `/` Dashboard | Four summary cards, latest alerts and events (auto-refresh every 5 s) |
| `/network` | Nodes (Active = event in the last 60 s), recent events, **Run simulation** button |
| `/alerts` | Alerts raised by the rules, with severity, status and incident link |
| `/incidents` | Incidents with Acknowledge / Contain / Resolve buttons |
| `/logs` | Event table with type and severity filters |
| `/about` | Server reachable or not, architecture, detection rules |

## Tests

```bash
python -m pytest tests/ -q          # all tests (needs: pip install pytest)
python tests/test_end_to_end.py     # the full demo workflow, no pytest needed
```

Every file in `tests/` also runs on its own with plain `python tests/<file>.py`. The tests use temporary
databases and free ports, so they never touch your real `cybershield.db` and do not need the server running.

## Project structure

```
app.py            Flask web dashboard
server.py         TCP server (threaded, newline-delimited JSON)
client.py         simulated nodes
detector.py       the three detection rules (pure functions)
database.py       SQLite layer shared by server.py and app.py
templates/        HTML pages (Jinja)
static/css/       style.css
tests/            automated tests
PROJECT_MASTER.md design decisions, milestones and status
```

`cybershield.db` is created automatically the first time `server.py` or `app.py` runs. To start from a
clean slate, stop both programs and delete that file.

## Troubleshooting

- **"Cannot reach the server"** from `client.py`: start `python server.py` first.
- **"Address already in use"**: another program is using port 9999 or 5000. Close the old copy, or change
  `PORT` in `server.py` and `client.py` (9999) or `app.py` (5000).
- **The About page says "Not reachable"**: `server.py` is not running (or uses a different port).
- **"No module named flask"**: activate the virtual environment and run `pip install -r requirements.txt`.
- **Run simulation shows an error**: it runs `client.py all`, so `server.py` must be running.