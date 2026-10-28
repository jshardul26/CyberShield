"""CyberShield web dashboard (Flask). Reads the SQLite database filled by server.py.

Run: python app.py   then open http://127.0.0.1:5000
"""
from flask import Flask, render_template, url_for

import database

HOST = "127.0.0.1"
PORT = 5000

app = Flask(__name__)

# (endpoint, label) in menu order. A link only appears once its page exists.
NAV = [("dashboard", "Dashboard"), ("network", "Network"), ("alerts", "Alerts"),
       ("incidents", "Incidents"), ("logs", "Logs"), ("about", "About")]


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


if __name__ == "__main__":
    database.init_db()
    app.run(host=HOST, port=PORT, debug=False)