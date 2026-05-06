from modules.mitre_mapper import get_mitre_info, get_severity_score
from datetime import datetime, timezone
from collections import defaultdict

# Şüpheli aktivite eşikleri
THRESHOLDS = {
    "failed_logins": 3,        # 5 dakikada 3+ başarısız giriş
    "api_calls_per_minute": 50, # Dakikada 50+ API çağrısı
    "regions_accessed": 3,      # Aynı anda 3+ farklı bölge
    "new_admin_policy": True,   # Admin politika eklenmesi
}

# Yüksek riskli olaylar
HIGH_RISK_EVENTS = {
    "DeleteTrail", "StopLogging", "DeleteBucket",
    "DeleteDBInstance", "CreateUser", "AttachUserPolicy",
    "AttachRolePolicy", "CreateAccessKey", "PutBucketPolicy",
    "RunInstances", "DeleteFlowLogs"
}

# Root hesap olayları
ROOT_EVENTS = {"ConsoleLogin", "CreateUser", "CreateAccessKey"}

class ThreatDetector:
    def __init__(self):
        self.alerts = []
        self.ip_tracker = defaultdict(list)
        self.failed_logins = defaultdict(list)
        self.api_tracker = defaultdict(list)

    def analyze_event(self, event):
        alerts = []
        event_name = event.get("EventName", "")
        username = event.get("Username", "Unknown")
        event_time = event.get("EventTime", datetime.now(timezone.utc))
        source_ip = event.get("SourceIPAddress", "Unknown")
        region = event.get("AwsRegion", "Unknown")

        mitre = get_mitre_info(event_name)

        # Root hesap aktivitesi
        if username == "root":
            alerts.append(self._create_alert(
                severity="CRITICAL",
                title="Root Hesap Aktivitesi!",
                description=f"Root hesap '{event_name}' işlemi yaptı",
                event_name=event_name,
                username=username,
                source_ip=source_ip,
                mitre=mitre,
                event_time=event_time
            ))

        # Yüksek riskli olay
        if event_name in HIGH_RISK_EVENTS:
            alerts.append(self._create_alert(
                severity=mitre["severity"],
                title=f"Yüksek Riskli Olay: {event_name}",
                description=mitre["description"],
                event_name=event_name,
                username=username,
                source_ip=source_ip,
                mitre=mitre,
                event_time=event_time
            ))

        # Başarısız giriş takibi
        if event_name == "ConsoleLogin":
            error = event.get("ErrorCode", "")
            if error:
                self.failed_logins[source_ip].append(event_time)
                recent = [t for t in self.failed_logins[source_ip]
                         if (datetime.now(timezone.utc) - t).seconds < 300]
                self.failed_logins[source_ip] = recent

                if len(recent) >= THRESHOLDS["failed_logins"]:
                    alerts.append(self._create_alert(
                        severity="HIGH",
                        title="Brute Force Saldırısı Tespit Edildi!",
                        description=f"{source_ip} adresinden {len(recent)} başarısız giriş denemesi",
                        event_name="ConsoleLoginFailure",
                        username=username,
                        source_ip=source_ip,
                        mitre=get_mitre_info("ConsoleLoginFailure"),
                        event_time=event_time
                    ))

        # Gece yarısı aktivitesi (00:00 - 06:00 UTC)
        if isinstance(event_time, datetime):
            hour = event_time.hour
            if 0 <= hour < 6 and event_name in HIGH_RISK_EVENTS:
                alerts.append(self._create_alert(
                    severity="HIGH",
                    title="Gece Yarısı Şüpheli Aktivite!",
                    description=f"Gece {hour}:00'da yüksek riskli işlem: {event_name}",
                    event_name=event_name,
                    username=username,
                    source_ip=source_ip,
                    mitre=mitre,
                    event_time=event_time
                ))

        return alerts

    def _create_alert(self, severity, title, description, event_name,
                      username, source_ip, mitre, event_time):
        return {
            "id": f"{event_name}_{int(datetime.now().timestamp())}",
            "severity": severity,
            "title": title,
            "description": description,
            "event_name": event_name,
            "username": username,
            "source_ip": source_ip,
            "mitre_id": mitre.get("technique_id", ""),
            "mitre_technique": mitre.get("technique", ""),
            "mitre_tactic": mitre.get("tactic", ""),
            "timestamp": event_time.strftime("%d.%m.%Y %H:%M:%S") if isinstance(event_time, datetime) else str(event_time),
            "score": get_severity_score(severity)
        }

detector = ThreatDetector()