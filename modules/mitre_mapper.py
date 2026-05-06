# MITRE ATT&CK Cloud Tactics Mapping
# https://attack.mitre.org/tactics/enterprise/

MITRE_TECHNIQUES = {
    # Initial Access
    "ConsoleLogin": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Initial Access",
        "severity": "MEDIUM",
        "description": "AWS Console'a giriş yapıldı"
    },
    "ConsoleLoginFailure": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "severity": "HIGH",
        "description": "Başarısız konsol giriş denemesi"
    },

    # Privilege Escalation
    "CreateUser": {
        "technique_id": "T1136",
        "technique": "Create Account",
        "tactic": "Persistence",
        "severity": "HIGH",
        "description": "Yeni IAM kullanıcısı oluşturuldu"
    },
    "AttachUserPolicy": {
        "technique_id": "T1098",
        "technique": "Account Manipulation",
        "tactic": "Persistence",
        "severity": "CRITICAL",
        "description": "Kullanıcıya politika eklendi"
    },
    "AttachRolePolicy": {
        "technique_id": "T1098",
        "technique": "Account Manipulation",
        "tactic": "Persistence",
        "severity": "CRITICAL",
        "description": "Role politika eklendi"
    },
    "CreateAccessKey": {
        "technique_id": "T1098.001",
        "technique": "Additional Cloud Credentials",
        "tactic": "Persistence",
        "severity": "HIGH",
        "description": "Yeni erişim anahtarı oluşturuldu"
    },

    # Defense Evasion
    "DeleteTrail": {
        "technique_id": "T1562.008",
        "technique": "Disable Cloud Logs",
        "tactic": "Defense Evasion",
        "severity": "CRITICAL",
        "description": "CloudTrail trail silindi!"
    },
    "StopLogging": {
        "technique_id": "T1562.008",
        "technique": "Disable Cloud Logs",
        "tactic": "Defense Evasion",
        "severity": "CRITICAL",
        "description": "CloudTrail logging durduruldu!"
    },
    "DeleteFlowLogs": {
        "technique_id": "T1562",
        "technique": "Impair Defenses",
        "tactic": "Defense Evasion",
        "severity": "HIGH",
        "description": "VPC Flow Logs silindi"
    },

    # Exfiltration
    "GetObject": {
        "technique_id": "T1530",
        "technique": "Data from Cloud Storage",
        "tactic": "Collection",
        "severity": "LOW",
        "description": "S3'ten dosya indirildi"
    },
    "PutBucketPolicy": {
        "technique_id": "T1530",
        "technique": "Data from Cloud Storage",
        "tactic": "Exfiltration",
        "severity": "HIGH",
        "description": "S3 bucket politikası değiştirildi"
    },

    # Discovery
    "ListBuckets": {
        "technique_id": "T1619",
        "technique": "Cloud Storage Object Discovery",
        "tactic": "Discovery",
        "severity": "LOW",
        "description": "S3 bucket'ları listelendi"
    },
    "ListUsers": {
        "technique_id": "T1087.004",
        "technique": "Cloud Account Discovery",
        "tactic": "Discovery",
        "severity": "LOW",
        "description": "IAM kullanıcıları listelendi"
    },
    "DescribeInstances": {
        "technique_id": "T1580",
        "technique": "Cloud Infrastructure Discovery",
        "tactic": "Discovery",
        "severity": "LOW",
        "description": "EC2 instance'ları keşfedildi"
    },

    # Impact
    "DeleteBucket": {
        "technique_id": "T1485",
        "technique": "Data Destruction",
        "tactic": "Impact",
        "severity": "CRITICAL",
        "description": "S3 bucket silindi!"
    },
    "DeleteDBInstance": {
        "technique_id": "T1485",
        "technique": "Data Destruction",
        "tactic": "Impact",
        "severity": "CRITICAL",
        "description": "RDS veritabanı silindi!"
    },
    "RunInstances": {
        "technique_id": "T1578.002",
        "technique": "Create Cloud Instance",
        "tactic": "Defense Evasion",
        "severity": "HIGH",
        "description": "Yeni EC2 instance başlatıldı"
    },
}

SEVERITY_COLORS = {
    "CRITICAL": "#f85149",
    "HIGH": "#f0883e",
    "MEDIUM": "#d29922",
    "LOW": "#58a6ff",
    "INFO": "#8b949e"
}

def get_mitre_info(event_name):
    return MITRE_TECHNIQUES.get(event_name, {
        "technique_id": "T0000",
        "technique": "Unknown",
        "tactic": "Unknown",
        "severity": "INFO",
        "description": f"AWS olayı: {event_name}"
    })

def get_severity_score(severity):
    scores = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 10}
    return scores.get(severity, 10)