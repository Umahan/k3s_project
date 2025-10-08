# Dockerfile
FROM python:3.11-slim

# Минимально: обновим пакеты и установим tzdata (опционально)
ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install pip deps
# No need for build-essential for pure-Python libs flask/requests/gunicorn
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy app
COPY app.py /app/app.py

# Create non-root user (good practice)
RUN adduser --disabled-password --gecos "" appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

# Use gunicorn for production; fallback to flask when needed.
# The module is "app:app" (file app.py, Flask object app)
CMD ["gunicorn", "-w", "3", "-b", "0.0.0.0:8080", "app:app"]
