# 🛡️ CloudSentinel

Gerçek zamanlı AWS tehdit tespiti ve güvenlik izleme platformu.

## Ne Yapıyor?

AWS CloudTrail loglarını gerçek zamanlı analiz ederek şüpheli aktiviteleri tespit eder, MITRE ATT&CK framework ile eşleştirir ve anında alarm üretir.

## Özellikler

- Gerçek zamanlı CloudTrail log analizi
- MITRE ATT&CK Cloud Techniques eşleştirme
- Brute force saldırısı tespiti
- Root hesap aktivite izleme
- Gece yarısı şüpheli aktivite tespiti
- Otomatik e-posta alarmları (CRITICAL ve HIGH)
- Canlı WebSocket dashboard
- En aktif kullanıcı, olay ve IP istatistikleri
- Arka planda 5 dakikada bir otomatik tarama

## Tespit Edilen Tehditler

- Root hesap aktivitesi
- Brute force giriş denemeleri
- IAM kullanıcı ve politika değişiklikleri
- CloudTrail logging kapatma girişimleri
- S3 bucket silme ve politika değişiklikleri
- Yeni EC2 instance başlatma
- VPC Flow Log silme
- Gece yarısı yüksek riskli operasyonlar

## MITRE ATT&CK Kapsamı

- Initial Access (T1078)
- Credential Access (T1110)
- Persistence (T1136, T1098)
- Defense Evasion (T1562)
- Collection (T1530)
- Discovery (T1619, T1087, T1580)
- Impact (T1485, T1578)

## Teknolojiler

- Python 3
- boto3 — AWS CloudTrail API
- Flask + Flask-SocketIO — Gerçek zamanlı dashboard
- python-dotenv — Güvenli credential yönetimi

## Kurulum

    git clone https://github.com/kaansoyturk/cloudsentinel.git
    cd cloudsentinel
    python3 -m venv venv
    source venv/bin/activate
    pip3 install boto3 flask flask-socketio python-dotenv colorama requests

## Yapılandırma

.env dosyası oluştur:

    AWS_ACCESS_KEY_ID=access_key_id
    AWS_SECRET_ACCESS_KEY=secret_access_key
    AWS_REGION=eu-central-1
    ALERT_EMAIL=email@gmail.com
    GMAIL_USER=email@gmail.com
    GMAIL_APP_PASSWORD=gmail_app_password

## Gerekli AWS Izinleri

- AWSCloudTrail_ReadOnlyAccess

## Kullanim

    python3 app.py

Tarayicide ac: http://localhost:5053

## Gelistirici

Kaan Soyturk — github.com/kaansoyturk