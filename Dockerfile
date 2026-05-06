# Python 3.11 base image
FROM python:3.11-slim

# Çalışma dizini
WORKDIR /app

# Bağımlılıkları kopyala ve yükle
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama dosyalarını kopyala
COPY . .

# Port
EXPOSE 5053

# Uygulamayı başlat
CMD ["python3", "app.py"]