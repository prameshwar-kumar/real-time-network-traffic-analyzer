import os
import threading

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

from app.sniffer.sniffer import start_sniffing
import app.dashboard.metrics as m


# -----------------------
# PATH FIX
# -----------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")


# -----------------------
# APP + SOCKET
# -----------------------
app = Flask(__name__, template_folder=TEMPLATE_DIR)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# -----------------------
# SNIFFER THREAD
# -----------------------
threading.Thread(target=start_sniffing, daemon=True).start()


# -----------------------
# SOCKET EMITTER
# -----------------------
def emit_metrics():
    while True:
        socketio.emit("update", m.metrics)
        socketio.sleep(1)


@socketio.on("connect")
def on_connect():
    socketio.start_background_task(emit_metrics)


# -----------------------
# ROUTES
# -----------------------
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/metrics")
def get_metrics():
    return jsonify(m.metrics)


# -----------------------
# RUN
# -----------------------
if __name__ == "__main__":
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)