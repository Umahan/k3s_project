# Dockerfile
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system deps (curl, jq) and clean apt lists
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
  && rm -rf /var/lib/apt/lists/*

# Copy requirements and install python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy app
COPY app.py /app/app.py

# Create non-root user and switch
RUN adduser --disabled-password --gecos "" appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

CMD ["gunicorn", "-w", "3", "-b", "0.0.0.0:8080", "app:app"]
