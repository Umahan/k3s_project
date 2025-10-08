#!/usr/bin/env python3
# app.py — robust webhook receiver

import os
import json
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

# Path to the shared secret (mounted from k8s Secret)
TOKEN_FILE = "/etc/webhook-secret/webhook_bearer"
EXPECTED_TOKEN = None
if os.path.exists(TOKEN_FILE):
    with open(TOKEN_FILE, "r") as f:
        EXPECTED_TOKEN = f.read().strip()
        app.logger.info("Loaded bearer token from %s (length=%d)", TOKEN_FILE, len(EXPECTED_TOKEN))

def try_parse_json_string(s):
    """If s is a string that contains JSON, try to parse it and return the object or None."""
    try:
        return json.loads(s)
    except Exception:
        return None

@app.route("/alert", methods=["POST"])
def alert():
    # 0) Diagnostics: headers + raw body snippet
    try:
        headers = {k: v for k, v in request.headers.items() if k in ("Content-Type","User-Agent","Authorization")}
        app.logger.info("Headers: %s", headers)
        raw = request.get_data(as_text=True)
        app.logger.info("Raw body length=%d chars. first 2000 chars: %s", len(raw), raw[:2000])
    except Exception:
        app.logger.exception("Failed to read raw request")

    # 1) Authorization (optional)
    if EXPECTED_TOKEN:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth.split(" ", 1)[1] != EXPECTED_TOKEN:
            app.logger.warning("Unauthorized request (bad/missing Bearer token)")
            return jsonify({"error": "unauthorized"}), 401

    # 2) Try standard JSON parsing via Flask
    alerts_obj = None
    try:
        alerts_obj = request.get_json(silent=True)
    except Exception:
        alerts_obj = None

    # 3) If that failed, try manual json.loads
    if alerts_obj is None:
        try:
            alerts_obj = json.loads(request.get_data(as_text=True))
        except Exception:
            alerts_obj = None

    # 4) Normalize various shapes into a list of alert-like dicts
    if isinstance(alerts_obj, list):
        alerts_list = alerts_obj
    elif isinstance(alerts_obj, dict) and "alerts" in alerts_obj and isinstance(alerts_obj["alerts"], list):
        alerts_list = alerts_obj["alerts"]
    elif isinstance(alerts_obj, dict):
        alerts_list = [alerts_obj]
    elif isinstance(alerts_obj, str):
        # string may be JSON array or JSON object
        parsed = try_parse_json_string(alerts_obj)
        if isinstance(parsed, list):
            alerts_list = parsed
        elif isinstance(parsed, dict):
            alerts_list = [parsed]
        else:
            # treat as single raw-string alert (unlikely)
            alerts_list = [alerts_obj]
    else:
        app.logger.error("Could not parse incoming payload as JSON. Type: %s", type(alerts_obj))
        return jsonify({"error": "invalid_json", "raw_length": len(request.get_data(as_text=True))}), 400

    processed = 0
    skipped = 0
    errors = []

    for idx, elem in enumerate(alerts_list):
        # If element is a JSON string (double-encoded), try to parse it
        if isinstance(elem, str):
            maybe = try_parse_json_string(elem)
            if isinstance(maybe, dict):
                elem = maybe
            else:
                app.logger.warning("Skipping element #%d: string not JSON-deserializable (len=%d)", idx, len(elem))
                skipped += 1
                continue

        if not isinstance(elem, dict):
            app.logger.warning("Skipping element #%d: unexpected type %s", idx, type(elem))
            skipped += 1
            continue

        # safe extraction of fields
        try:
            labels = elem.get("labels") if isinstance(elem.get("labels", {}), dict) else {}
            ann = elem.get("annotations") if isinstance(elem.get("annotations", {}), dict) else {}
            name = labels.get("alertname", "<no-name>")
            instance = labels.get("instance", labels.get("host", "<unknown>"))
            summary = ann.get("summary") or ann.get("description") or ""
            msg = f"[{elem.get('status','?')}] {name} on {instance} — {summary}"
            app.logger.info("ALERT normalized: %s", msg)
            # here you can forward to Telegram / Slack / create ticket etc.
            processed += 1
        except Exception as e:
            app.logger.exception("Failed to process element #%d", idx)
            errors.append(str(e))
            skipped += 1
            continue

    return jsonify({
        "received_raw_count": len(alerts_list),
        "processed": processed,
        "skipped": skipped,
        "errors": errors
    }), 200

# ДОБАВЛЕНО: Главный блок запуска (для локального теста)
if __name__ == '__main__':
    port = int(os.environ.get('SERVER_PORT', os.environ.get('PORT', 8080)))
    app.logger.info(f"Starting Flask server on port {port} (dev mode)")
    # слушаем на 0.0.0.0 чтобы порт-forward / контейнерная сеть работали
    app.run(host='0.0.0.0', port=port, debug=False)
