from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from models import db, Alert, ScanEvent
from modules.cloudtrail_monitor import get_recent_events, get_event_statistics
from modules.alert_manager import process_alerts
from modules.slack_notifier import send_slack_alert, send_slack_summary
from dotenv import load_dotenv
import threading
import time
import os

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = "cloudsentinel-secret-2026"
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "postgresql://cloudsentinel:cloudsentinel123@localhost:5432/cloudsentinel"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "eu-central-1")

all_alerts = []
last_scan_time = None

def save_alerts_to_db(alerts):
    with app.app_context():
        for alert in alerts:
            db_alert = Alert(
                severity=alert.get("severity"),
                title=alert.get("title"),
                description=alert.get("description"),
                event_name=alert.get("event_name"),
                username=alert.get("username"),
                source_ip=alert.get("source_ip"),
                mitre_id=alert.get("mitre_id"),
                mitre_technique=alert.get("mitre_technique"),
                mitre_tactic=alert.get("mitre_tactic")
            )
            db.session.add(db_alert)
        db.session.commit()

def background_monitor():
    global all_alerts, last_scan_time
    while True:
        try:
            print("⚡ Arka plan taraması başlıyor...")
            results = get_recent_events(AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION, hours=1)

            if results["alerts"]:
                new_alerts = results["alerts"]
                all_alerts = (new_alerts + all_alerts)[:100]
                process_alerts(new_alerts)

                # PostgreSQL'e kaydet
                save_alerts_to_db(new_alerts)

                # Slack bildirimi
                for alert in new_alerts:
                    if alert.get("severity") in ["CRITICAL", "HIGH"]:
                        send_slack_alert(alert)

                socketio.emit("new_alerts", {"alerts": new_alerts, "count": len(new_alerts)})
                print(f"🚨 {len(new_alerts)} yeni alert!")

            last_scan_time = time.strftime("%H:%M:%S")
            socketio.emit("scan_complete", {"time": last_scan_time, "total": results["total_events"]})

        except Exception as e:
            print(f"❌ Arka plan tarama hatası: {e}")

        time.sleep(300)

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

    # PostgreSQL'e kaydet
    if results["alerts"]:
        save_alerts_to_db(results["alerts"])
        for alert in results["alerts"]:
            if alert.get("severity") in ["CRITICAL", "HIGH"]:
                send_slack_alert(alert)

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

@app.route("/api/alerts/history")
def get_alert_history():
    try:
        alerts = Alert.query.order_by(Alert.created_at.desc()).limit(100).all()
        return jsonify({"alerts": [a.to_dict() for a in alerts]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def acknowledge_alert(alert_id):
    try:
        alert = Alert.query.get(alert_id)
        if alert:
            alert.acknowledged = True
            db.session.commit()
            return jsonify({"success": True})
        return jsonify({"error": "Alert bulunamadı"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/stats")
def get_stats():
    try:
        total = Alert.query.count()
        critical = Alert.query.filter_by(severity="CRITICAL").count()
        high = Alert.query.filter_by(severity="HIGH").count()
        unacked = Alert.query.filter_by(acknowledged=False).count()
        return jsonify({
            "total": total,
            "critical": critical,
            "high": high,
            "unacknowledged": unacked
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@socketio.on("connect")
def on_connect():
    print("🔌 Client bağlandı")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("✅ Veritabanı hazır!")

    monitor_thread = threading.Thread(target=background_monitor, daemon=True)
    monitor_thread.start()
    print("⚡ CloudSentinel başlatıldı — arka plan monitörü aktif")
    socketio.run(app, host="0.0.0.0", debug=True, port=5053, allow_unsafe_werkzeug=True)