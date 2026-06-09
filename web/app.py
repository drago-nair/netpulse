from collections import deque
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from utils.alert import Alert
import config

app = Flask(__name__)
app.config["SECRET_KEY"] = "netpulse-secret-key"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

_recent_alerts = deque(maxlen=config.MAX_ALERTS_FEED)


def emit_alert(alert: Alert):
    data = alert.to_dict()
    _recent_alerts.append(data)
    socketio.emit("alert", data)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def get_alerts():
    return jsonify(list(_recent_alerts))


@socketio.on("connect")
def on_connect():
    for alert in list(_recent_alerts):
        socketio.emit("alert", alert)


def run(sniffer):
    sniffer.start()
    socketio.run(app, host=config.WEB_HOST, port=config.WEB_PORT, debug=False)