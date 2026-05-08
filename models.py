from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    event_name = db.Column(db.String(100))
    username = db.Column(db.String(100))
    source_ip = db.Column(db.String(50))
    mitre_id = db.Column(db.String(20))
    mitre_technique = db.Column(db.String(100))
    mitre_tactic = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "event_name": self.event_name,
            "username": self.username,
            "source_ip": self.source_ip,
            "mitre_id": self.mitre_id,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "timestamp": self.created_at.strftime("%d.%m.%Y %H:%M:%S"),
            "acknowledged": self.acknowledged
        }

class ScanEvent(db.Model):
    __tablename__ = "scan_events"

    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(100))
    username = db.Column(db.String(100))
    source_ip = db.Column(db.String(50))
    region = db.Column(db.String(50))
    error_code = db.Column(db.String(100))
    event_time = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "event_name": self.event_name,
            "username": self.username,
            "source_ip": self.source_ip,
            "region": self.region,
            "error_code": self.error_code,
            "event_time": self.event_time.strftime("%d.%m.%Y %H:%M:%S") if self.event_time else None
        }