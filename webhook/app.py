#!/usr/bin/env python3
# app.py — robust webhook receiver with Telegram forwarding + logging

import os
import json
import logging
import time
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

# Secrets paths
TOKEN_FILE = "/etc/webhook-secret/webhook_bearer"
EXPECTED_TOKEN = None
if os.path.exists(TOKEN_FILE):
    with open(TOKEN_FILE, "r") as f:
        EXPECTED_TOKEN = f.read().strip()
        app.logger.info("Loaded bearer token from %s (len=%d)", TOKEN_FILE, len(EXPECTED_TOKEN or ""))

# Telegram config from env (mounted from k8s Secret via env)
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

def try_parse_json_string(s):
    try:
        return json.loads(s)
    except Exception:
        return None

def send_telegram(text, max_retries=3):
    """Send message to Telegram, with retry and rich logging. Returns (ok, resp_json_or_text)."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        app.logger.warning("Telegram credentials not configured (TELEGRAM_BOT_TOKEN/CHAT_ID missing). Skipping send.")
        return False, "no-creds"

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.post(url, data=payload, timeout=10)
            app.logger.info("Telegram POST attempt %d -> status=%s, text=%s", attempt, r.status_code, r.text[:200])
            if r.status_code == 200:
                try:
                    j = r.json()
                    return j.get("ok", False), j
                except Exception:
                    return False, r.text
            else:
                # maybe retry for 5xx
                if 500 <= r.status_code < 600:
                    app.logger.warning("Server error from Telegram (%d). Retrying after backoff.", r.status_code)
                    time.sleep(2 ** attempt)
                    continue
                return False, r.text
        except requests.exceptions.RequestException as e:
            app.logger.exception("Network error sending to Telegram on attempt %d", attempt)
            time.sleep(1 * attempt)
    return False, "max_retries_exceeded"

@app.route("/alert", methods=["POST"])
def alert():
    # log headers & raw body
    headers = {k: v for k, v in request.headers.items() if k in ("Content-Type", "User-Agent", "Authorization")}
    app.logger.info("Headers: %s", headers)
    raw = request.get_data(as_text=True)
    app.logger.info("Raw body length=%d. first 2000 chars: %s", len(raw), raw[:2000])

    # auth
    if EXPECTED_TOKEN:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth.split(" ", 1)[1] != EXPECTED_TOKEN:
            app.logger.warning("Unauthorized request (bad token). header=%s", auth)
            return jsonify({"error": "unauthorized"}), 401

    # try parse
    alerts_obj = request.get_json(silent=True)
    if alerts_obj is None:
        try:
            alerts_obj = json.loads(raw)
        except Exception:
            alerts_obj = None

    if isinstance(alerts_obj, dict) and "alerts" in alerts_obj and isinstance(alerts_obj["alerts"], list):
        alerts_list = alerts_obj["alerts"]
    elif isinstance(alerts_obj, list):
        alerts_list = alerts_obj
    elif isinstance(alerts_obj, dict):
        alerts_list = [alerts_obj]
    else:
        return jsonify({"error": "invalid_json"}), 400

    processed = 0
    skipped = 0
    errors = []

    for idx, a in enumerate(alerts_list):
        if isinstance(a, str):
            parsed = try_parse_json_string(a)
            if isinstance(parsed, dict):
                a = parsed
            else:
                app.logger.warning("Skipping element #%d: string not parseable", idx)
                skipped += 1
                continue

        if not isinstance(a, dict):
            skipped += 1
            continue

        try:
            labels = a.get("labels", {}) if isinstance(a.get("labels", {}), dict) else {}
            ann = a.get("annotations", {}) if isinstance(a.get("annotations", {}), dict) else {}
            name = labels.get("alertname", "<no-name>")
            instance = labels.get("instance", labels.get("host", "<unknown>"))
            summary = ann.get("summary") or ann.get("description") or ""
            status = a.get("status", "?")
            human = f"[{status}] {name} on {instance} — {summary}"
            app.logger.info("ALERT normalized: %s", human)

            # Forward to Telegram (synchronous)
            ok, resp = send_telegram(human)
            if ok:
                app.logger.info("Forwarded to Telegram: ok")
            else:
                app.logger.warning("Failed to forward to Telegram: %s", resp)

            processed += 1
        except Exception as e:
            app.logger.exception("Error processing element #%d", idx)
            errors.append(str(e))
            skipped += 1

    return jsonify({"received_raw_count": len(alerts_list), "processed": processed, "skipped": skipped, "errors": errors}), 200

if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", os.environ.get("PORT", 8080)))
    app.logger.info("Starting Flask dev server on 0.0.0.0:%d", port)
    app.run(host="0.0.0.0", port=port, debug=False)
