import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

SEVERITY_EMOJIS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪"
}

SEVERITY_COLORS = {
    "CRITICAL": "#f85149",
    "HIGH": "#f0883e",
    "MEDIUM": "#d29922",
    "LOW": "#58a6ff",
    "INFO": "#8b949e"
}

def send_slack_alert(alert):
    if not SLACK_WEBHOOK_URL:
        print("⚠ Slack webhook URL tanımlı değil")
        return False

    severity = alert.get("severity", "INFO")
    emoji = SEVERITY_EMOJIS.get(severity, "⚪")
    color = SEVERITY_COLORS.get(severity, "#8b949e")

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} CloudSentinel Alert — {severity}"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Başlık:*\n{alert.get('title', '')}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Açıklama:*\n{alert.get('description', '')}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Kullanıcı:*\n{alert.get('username', 'Bilinmiyor')}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*IP Adresi:*\n{alert.get('source_ip', 'Bilinmiyor')}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*MITRE:*\n{alert.get('mitre_id', '')} — {alert.get('mitre_tactic', '')}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Zaman:*\n{alert.get('timestamp', '')}"
                            }
                        ]
                    }
                ]
            }
        ]
    }

    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        if response.status_code == 200:
            print(f"📨 Slack bildirimi gönderildi: {alert.get('title', '')}")
            return True
        else:
            print(f"❌ Slack hatası: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Slack bağlantı hatası: {e}")
        return False

def send_slack_summary(total_events, alert_count, critical_count):
    if not SLACK_WEBHOOK_URL:
        return False

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "☁️ CloudSentinel — Tarama Özeti"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Toplam Olay:*\n{total_events}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Alert Sayısı:*\n{alert_count}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Kritik Alert:*\n{critical_count}"
                    }
                ]
            }
        ]
    }

    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        return response.status_code == 200
    except:
        return False