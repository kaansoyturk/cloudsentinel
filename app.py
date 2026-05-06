from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from modules.cloudtrail_monitor import get_recent_events, get_event_statistics
from modules.alert_manager import process_alerts
from dotenv import load_dotenv
import threading
import time
import os

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = "cloudsentinel-secret-2026"
socketio = SocketIO(app, cors_allowed_origins="*")

AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "eu-central-1")

# Geçmiş alertler
all_alerts = []
last_scan_time = None

def background_monitor():
    """Arka planda her 5 dakikada bir tara"""
    global all_alerts, last_scan_time
    while True:
        try:
            print("⚡ Arka plan taraması başlıyor...")
            results = get_recent_events(AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION, hours=1)

            if results["alerts"]:
                new_alerts = results["alerts"]
                all_alerts = (new_alerts + all_alerts)[:100]
                process_alerts(new_alerts)

                # Canlı bildirim gönder
                socketio.emit("new_alerts", {"alerts": new_alerts, "count": len(new_alerts)})
                print(f"🚨 {len(new_alerts)} yeni alert!")

            last_scan_time = time.strftime("%H:%M:%S")
            socketio.emit("scan_complete", {"time": last_scan_time, "total": results["total_events"]})

        except Exception as e:
            print(f"❌ Arka plan tarama hatası: {e}")

        time.sleep(300)  # 5 dakika bekle

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan")
def scan():
    global all_alerts, last_scan_time

    print("\n🔍 Manuel tarama başlıyor...")
    results = get_recent_events(AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION, hours=24)

    if results.get("error"):
        return jsonify({"error": results["error"]}), 500

    stats = get_event_statistics(results["events"])
    alert_summary = process_alerts(results["alerts"])

    all_alerts = (results["alerts"] + all_alerts)[:100]
    last_scan_time = time.strftime("%H:%M:%S")

    return jsonify({
        "total_events": results["total_events"],
        "alerts": results["alerts"][:50],
        "alert_summary": alert_summary,
        "statistics": stats,
        "scan_time": last_scan_time
    })

@app.route("/api/alerts")
def get_alerts():
    return jsonify({"alerts": all_alerts[:50]})

@socketio.on("connect")
def on_connect():
    print("🔌 Client bağlandı")

if __name__ == "__main__":
    # Arka plan monitörünü başlat
    monitor_thread = threading.Thread(target=background_monitor, daemon=True)
    monitor_thread.start()
    print("⚡ CloudSentinel başlatıldı — arka plan monitörü aktif")
    socketio.run(app, debug=True, port=5053, allow_unsafe_werkzeug=True)