import boto3
from datetime import datetime, timezone, timedelta
from modules.threat_detector import detector

def get_recent_events(access_key, secret_key, region, hours=24):
    """Son X saatteki CloudTrail olaylarını getir"""
    results = {
        "events": [],
        "alerts": [],
        "total_events": 0,
        "error": None
    }

    try:
        ct = boto3.client(
            "cloudtrail",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        paginator = ct.get_paginator("lookup_events")
        pages = paginator.paginate(
            StartTime=start_time,
            EndTime=datetime.now(timezone.utc),
            PaginationConfig={"MaxItems": 200, "PageSize": 50}
        )

        all_events = []
        for page in pages:
            all_events.extend(page.get("Events", []))

        results["total_events"] = len(all_events)

        for event in all_events:
            event_data = {
                "EventName": event.get("EventName", ""),
                "Username": event.get("Username", "Unknown"),
                "EventTime": event.get("EventTime", datetime.now(timezone.utc)),
                "SourceIPAddress": "",
                "AwsRegion": region,
                "ErrorCode": ""
            }

            # CloudTrail event detaylarından IP al
            if event.get("CloudTrailEvent"):
                import json
                try:
                    detail = json.loads(event["CloudTrailEvent"])
                    event_data["SourceIPAddress"] = detail.get("sourceIPAddress", "")
                    event_data["AwsRegion"] = detail.get("awsRegion", region)
                    event_data["ErrorCode"] = detail.get("errorCode", "")
                except:
                    pass

            results["events"].append(event_data)

            # Tehdit analizi
            alerts = detector.analyze_event(event_data)
            results["alerts"].extend(alerts)

    except Exception as e:
        results["error"] = str(e)

    return results

def get_event_statistics(events):
    """Olay istatistiklerini hesapla"""
    stats = {
        "by_user": {},
        "by_event": {},
        "by_ip": {},
        "by_hour": {}
    }

    for event in events:
        username = event.get("Username", "Unknown")
        event_name = event.get("EventName", "Unknown")
        ip = event.get("SourceIPAddress", "Unknown")
        event_time = event.get("EventTime")

        stats["by_user"][username] = stats["by_user"].get(username, 0) + 1
        stats["by_event"][event_name] = stats["by_event"].get(event_name, 0) + 1
        stats["by_ip"][ip] = stats["by_ip"].get(ip, 0) + 1

        if isinstance(event_time, datetime):
            hour = str(event_time.hour)
            stats["by_hour"][hour] = stats["by_hour"].get(hour, 0) + 1

    # En aktif 5'i al
    stats["top_users"] = sorted(stats["by_user"].items(), key=lambda x: x[1], reverse=True)[:5]
    stats["top_events"] = sorted(stats["by_event"].items(), key=lambda x: x[1], reverse=True)[:5]
    stats["top_ips"] = sorted(stats["by_ip"].items(), key=lambda x: x[1], reverse=True)[:5]

    return stats