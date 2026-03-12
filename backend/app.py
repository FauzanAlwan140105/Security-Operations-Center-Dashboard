import os
import time
import threading
from flask import Flask, send_from_directory, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS
from monitor import WebsiteMonitor

app = Flask(__name__, static_folder=None)
app.config["SECRET_KEY"] = os.urandom(32).hex()
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

monitor = WebsiteMonitor()

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

SCAN_INTERVAL = 15


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/css/<path:filename>")
def css_files(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "css"), filename)


@app.route("/js/<path:filename>")
def js_files(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "js"), filename)


@app.route("/api/status")
def api_status():
    return jsonify(monitor.get_latest())


@app.route("/api/dashboard")
def api_dashboard():
    return jsonify(monitor.get_dashboard_summary())


@app.route("/api/events")
def api_events():
    site = request.args.get("site", "all")
    limit = int(request.args.get("limit", 50))
    return jsonify(monitor.get_events(limit, site))


@app.route("/api/history/<site_key>")
def api_history(site_key):
    limit = int(request.args.get("limit", 100))
    return jsonify(monitor.get_history(site_key, limit))


@app.route("/api/history")
def api_all_history():
    limit = int(request.args.get("limit", 100))
    return jsonify(monitor.get_all_history(limit))


@app.route("/api/logs")
def api_logs():
    limit = int(request.args.get("limit", 100))
    return jsonify(monitor.get_logs(limit))


@app.route("/api/scan")
def api_scan_now():
    results = monitor.scan_all()
    socketio.emit("scan_complete", results)
    return jsonify({"status": "ok", "results": results})


@socketio.on("connect")
def handle_connect():
    print(f"[SOC] Client connected")
    latest = monitor.get_latest()
    if latest:
        socketio.emit("scan_complete", latest)
    socketio.emit("dashboard_update", monitor.get_dashboard_summary())
    socketio.emit("events_update", monitor.get_events(30))
    socketio.emit("logs_update", monitor.get_logs(50))


@socketio.on("disconnect")
def handle_disconnect():
    print(f"[SOC] Client disconnected")


@socketio.on("request_scan")
def handle_request_scan():
    results = monitor.scan_all()
    socketio.emit("scan_complete", results)
    socketio.emit("dashboard_update", monitor.get_dashboard_summary())
    socketio.emit("events_update", monitor.get_events(30))


@socketio.on("request_dashboard")
def handle_request_dashboard():
    socketio.emit("dashboard_update", monitor.get_dashboard_summary())


@socketio.on("request_events")
def handle_request_events(data=None):
    site = data.get("site", "all") if data else "all"
    limit = data.get("limit", 30) if data else 30
    socketio.emit("events_update", monitor.get_events(limit, site))


@socketio.on("request_logs")
def handle_request_logs():
    socketio.emit("logs_update", monitor.get_logs(100))


def monitoring_loop():
    print("[SOC] Starting monitoring loop...")
    time.sleep(2)
    while True:
        try:
            print(f"[SOC] Scanning all websites...")
            results = monitor.scan_all()

            socketio.emit("scan_complete", results)
            socketio.emit("dashboard_update", monitor.get_dashboard_summary())
            socketio.emit("events_update", monitor.get_events(30))
            socketio.emit("logs_update", monitor.get_logs(50))

            for key, res in results.items():
                status = res["status"].upper()
                rtime = res["response_time_ms"]
                score = res["security_score"]
                ssl_ok = "Valid" if res["ssl"].get("valid") else "INVALID"
                print(
                    f"  [{key}] {status} | {rtime}ms | Score: {score}% | SSL: {ssl_ok}"
                )

        except Exception as e:
            print(f"[SOC] Monitoring error: {e}")

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    print("=" * 60)
    print("  SOC Dashboard — Security Operations Center")
    print("  Real-time Website Monitoring Backend")
    print("=" * 60)
    print(f"  Monitoring:")
    print(f"    1. himatikafmipaunhas.id")
    print(f"    2. ukmfotografiunhas.com")
    print(f"  Scan interval: {SCAN_INTERVAL}s")
    print(f"  Dashboard: http://localhost:5000")
    print("=" * 60)

    monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
    monitor_thread.start()

    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
