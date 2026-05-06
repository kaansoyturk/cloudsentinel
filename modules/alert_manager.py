import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
ALERT_EMAIL = os.getenv("ALERT_EMAIL")

sent_alerts = set()

def send_alert_email(alert):
    try:
        alert_id = alert.get("id", "")
        if alert_id in sent_alerts:
            return
        sent_alerts.add(alert_id)

        msg = MIMEMultipart()
        msg["From"] = GMAIL_USER
        msg["To"] = ALERT_EMAIL
        msg["Subject"] = f"🚨 CloudSentinel [{alert['severity']}] {alert['title']}"

        body = f"""
CloudSentinel Tehdit Alarmı
{'='*50}

🔴 Seviye    : {alert['severity']}
📋 Başlık    : {alert['title']}
📝 Açıklama  : {alert['description']}

👤 Kullanıcı : {alert['username']}
🌐 IP Adresi : {alert['source_ip']}
⏰ Zaman     : {alert['timestamp']}

MITRE ATT&CK
{'='*50}
🎯 Teknik ID : {alert['mitre_id']}
🎯 Teknik    : {alert['mitre_technique']}
🎯 Taktik    : {alert['mitre_tactic']}

{'='*50}
Bu alarm CloudSentinel tarafından otomatik oluşturuldu.
        """

        msg.attach(MIMEText(body, "plain"))
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, ALERT_EMAIL, msg.as_string())
        server.quit()
        print(f"📧 Alert maili gönderildi: {alert['title']}")

    except Exception as e:
        print(f"❌ Mail gönderilemedi: {e}")

def process_alerts(alerts):
    critical_alerts = [a for a in alerts if a["severity"] == "CRITICAL"]
    high_alerts = [a for a in alerts if a["severity"] == "HIGH"]

    # Sadece CRITICAL ve HIGH için mail gönder
    for alert in critical_alerts + high_alerts:
        send_alert_email(alert)

    return {
        "total": len(alerts),
        "critical": len(critical_alerts),
        "high": len(high_alerts),
        "medium": len([a for a in alerts if a["severity"] == "MEDIUM"]),
        "low": len([a for a in alerts if a["severity"] == "LOW"]),
        "info": len([a for a in alerts if a["severity"] == "INFO"])
    }