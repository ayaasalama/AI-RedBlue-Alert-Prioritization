from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import ipaddress
import logging
import time

import joblib
import numpy as np
import pandas as pd
from opensearchpy import OpenSearch
from opensearchpy.helpers import bulk

# 1. SETTINGS
BASE_DIR = Path(__file__).resolve().parents[1]
MODELS_DIR = BASE_DIR / "models"
LIVE_DIR = BASE_DIR / "live_scorer"
LIVE_DIR.mkdir(exist_ok=True)

MODEL_PATH = MODELS_DIR / "isolation_forest_dataset_B.pkl"
SCALER_PATH = MODELS_DIR / "standard_scaler_dataset_B.pkl"
FEATURES_PATH = MODELS_DIR / "feature_columns_dataset_B.pkl"
CALIBRATION_PATH = MODELS_DIR / "score_calibration_dataset_B.pkl"

SEEN_IDS_PATH = LIVE_DIR / "seen_ids.txt"

OPENSEARCH_HOST = "192.168.79.129"
OPENSEARCH_PORT = 9200
OPENSEARCH_USER = "admin"
OPENSEARCH_PASSWORD = "admin"

SOURCE_INDEX = "wazuh-alerts-*"
TARGET_INDEX = "live-priority-events"

POLL_SECONDS = 20
LOOKBACK_WINDOW = "now-10m"
FINAL_RISK_THRESHOLD = 0.60

SUPPORTED_EVENTS = [4624, 4625, 4672, 4688, 5140, 7045]

SPRAY_MIN_ATTEMPTS = 4
SPRAY_MIN_USERS = 3
GUESSING_MIN_ATTEMPTS = 5

# 2. LOGGING
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("live-scorer")

# 3. LOAD MODEL FILES
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
feature_columns = joblib.load(FEATURES_PATH)
calibration = joblib.load(CALIBRATION_PATH)

raw_lower = calibration["raw_score_lower"]
raw_upper = calibration["raw_score_upper"]

if len(feature_columns) != scaler.n_features_in_:
    raise ValueError("Saved feature list and scaler do not match.")

# 4. CONNECT TO OPENSEARCH
client = OpenSearch(
    hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
    http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
    use_ssl=True,
    verify_certs=False,
    ssl_show_warn=False,
    timeout=60,
)

# 5. HELPERS
def safe_int(value, default=0):
    try:
        if value in (None, "", "-", "unknown"):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default

def safe_text(value, default="unknown"):
    text = "" if value is None else str(value).strip()
    return text if text else default

def eventdata(alert):
    return alert.get("data", {}).get("win", {}).get("eventdata", {})

def load_seen_ids():
    if not SEEN_IDS_PATH.exists():
        return set()
    return set(SEEN_IDS_PATH.read_text(encoding="utf-8").splitlines())

def save_seen_ids(seen_ids):
    SEEN_IDS_PATH.write_text("\n".join(sorted(seen_ids)), encoding="utf-8")

# 6. FIELD EXTRACTION
def get_event_id(alert):
    data = alert.get("data", {})
    system = data.get("win", {}).get("system", {})

    for value in [
        system.get("eventID"),
        system.get("eventId"),
        data.get("event_id"),
        data.get("eventID"),
        alert.get("event_id"),
    ]:
        result = safe_int(value, None)
        if result is not None:
            return result

    return 0

def get_user(alert, event_id):
    data = alert.get("data", {})
    details = eventdata(alert)

    if event_id in (4624, 4625):
        candidates = [
            details.get("targetUserName"),
            details.get("targetUser"),
            details.get("accountName"),
            details.get("subjectUserName"),
        ]
    else:
        candidates = [
            details.get("subjectUserName"),
            details.get("accountName"),
            details.get("targetUserName"),
            details.get("user"),
        ]

    candidates += [
        data.get("dstuser"),
        data.get("srcuser"),
        data.get("user"),
    ]

    for value in candidates:
        user = safe_text(value, "")
        if user and user.lower() not in {"-", "unknown", "none", "null"}:
            return user

    return "unknown"

def is_real_user(user):
    return (
        user != "unknown"
        and user.upper() != "ANONYMOUS LOGON"
        and not user.endswith("$")
    )

def get_host(alert):
    return safe_text(alert.get("agent", {}).get("name"), "unknown")

def get_host_ip(alert):
    return safe_text(alert.get("agent", {}).get("ip"), "0.0.0.0")

def get_source_ip(alert):
    data = alert.get("data", {})
    details = eventdata(alert)

    candidates = [
        data.get("srcip"),
        data.get("src_ip"),
        data.get("source_ip"),
        details.get("ipAddress"),
        details.get("sourceNetworkAddress"),
        details.get("sourceIp"),
        details.get("clientAddress"),
        alert.get("srcip"),
    ]

    ipv4 = []
    ipv6 = []

    for value in candidates:
        if value is None:
            continue

        text = str(value).strip()

        if text.lower() in {"", "-", "unknown", "none", "null", "::1", "127.0.0.1"}:
            continue

        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            continue

        if address.version == 4:
            ipv4.append(str(address))
        else:
            ipv6.append(str(address))

    if ipv4:
        return ipv4[0]
    if ipv6:
        return ipv6[0]
    return None

def get_logon_type(alert):
    data = alert.get("data", {})
    details = eventdata(alert)

    for value in [
        details.get("logonType"),
        details.get("logon_type"),
        data.get("logon_type"),
    ]:
        result = safe_int(value, None)
        if result is not None:
            return result

    return 0

def get_asset_criticality(host):
    name = host.upper()

    if "DC01" in name or "DOMAIN" in name:
        return 1.00
    if "FINANCE" in name:
        return 0.80
    if "IT-PC01" in name or name.startswith("IT"):
        return 0.60

    return 0.50

# 7. ROLLING 10-MINUTE COUNTS
def build_window_stats(hits):
    stats = defaultdict(
        lambda: {
            "failed": 0,
            "success": 0,
            "attempts": 0,
            "users": set(),
            "hosts": set(),
        }
    )

    for hit in hits:
        alert = hit["_source"]
        event_id = get_event_id(alert)
        source_ip = get_source_ip(alert)

        if event_id not in SUPPORTED_EVENTS or source_ip is None:
            continue

        user = get_user(alert, event_id)

        # Ignore machine/anonymous users from correlation counts.
        if event_id in (4624, 4625) and not is_real_user(user):
            continue

        stats[source_ip]["attempts"] += 1
        stats[source_ip]["hosts"].add(get_host(alert))
        stats[source_ip]["users"].add(user.lower())

        if event_id == 4625:
            stats[source_ip]["failed"] += 1
        elif event_id == 4624:
            stats[source_ip]["success"] += 1

    result = {}

    for source_ip, values in stats.items():
        result[source_ip] = {
            "failed_login_count": values["failed"],
            "successful_login_count": values["success"],
            "same_source_ip_attempts": values["attempts"],
            "unique_users_targeted": max(1, len(values["users"])),
            "distinct_hosts_accessed": max(1, len(values["hosts"])),
        }

    return result

# 8. FEATURE CREATION
def build_feature_row(alert, window_stats):
    event_id = get_event_id(alert)
    source_ip = get_source_ip(alert)
    host = get_host(alert)
    logon_type = get_logon_type(alert)

    try:
        hour = int(pd.to_datetime(alert.get("@timestamp"), utc=True).hour)
    except Exception:
        hour = datetime.now(timezone.utc).hour

    counts = window_stats.get(source_ip, {}) if source_ip else {}

    row = {
        "rule_level": safe_int(alert.get("rule", {}).get("level"), 3),
        "failed_login_count": counts.get(
            "failed_login_count", 1 if event_id == 4625 else 0
        ),
        "successful_login_count": counts.get(
            "successful_login_count", 1 if event_id == 4624 else 0
        ),
        "same_source_ip_attempts": counts.get("same_source_ip_attempts", 1),
        "unique_users_targeted": counts.get("unique_users_targeted", 1),
        "distinct_hosts_accessed": counts.get("distinct_hosts_accessed", 1),
        "hour_of_day": hour,
        "is_after_hours": int(hour < 7 or hour >= 20),
        "is_remote_logon": int(logon_type in (3, 10)),
        "logon_type": logon_type,
        "asset_criticality": get_asset_criticality(host),
    }

    for supported_id in SUPPORTED_EVENTS:
        row[f"event_{supported_id}"] = int(event_id == supported_id)

    return row

# 9. SCORING
def normalize_anomaly(raw_score):
    denominator = raw_upper - raw_lower

    if denominator == 0:
        return 0.0

    value = (raw_score - raw_lower) / denominator
    return float(np.clip(value, 0.0, 1.0))

def calculate_context(row):
    authentication = min(row["failed_login_count"] / 10.0, 1.0)

    user_spread = min(max(row["unique_users_targeted"] - 1, 0) / 4.0, 1.0)
    host_spread = min(max(row["distinct_hosts_accessed"] - 1, 0) / 2.0, 1.0)
    spread = max(user_spread, host_spread)

    remote_sequence = 0.5 if row["is_remote_logon"] else 0.0

    if row["failed_login_count"] >= 3 and row["successful_login_count"] >= 1:
        remote_sequence += 0.5

    remote_sequence = min(remote_sequence, 1.0)

    if row["event_7045"]:
        event_score = 1.00
    elif row["event_5140"]:
        event_score = 0.70
    elif row["event_4672"]:
        event_score = 0.50
    elif row["event_4688"]:
        event_score = 0.40
    else:
        event_score = 0.00

    score = (
        0.35 * authentication
        + 0.20 * spread
        + 0.20 * remote_sequence
        + 0.20 * event_score
        + 0.05 * row["is_after_hours"]
    )

    return float(np.clip(score, 0.0, 1.0))

def calculate_risk(row, anomaly, context):
    score = (
        0.40 * anomaly
        + 0.25 * (row["rule_level"] / 15.0)
        + 0.20 * row["asset_criticality"]
        + 0.15 * context
    )
    return float(np.clip(score, 0.0, 1.0))

# 10. MITRE AND RESPONSE
def map_mitre(row, priority):
    if row["event_4625"]:
        if (
            row["failed_login_count"] >= SPRAY_MIN_ATTEMPTS
            and row["unique_users_targeted"] >= SPRAY_MIN_USERS
        ):
            return "T1110.003 - Password Spraying"

        if (
            row["failed_login_count"] >= GUESSING_MIN_ATTEMPTS
            and row["unique_users_targeted"] == 1
        ):
            return "T1110.001 - Password Guessing"

        return "Authentication Failure - No ATT&CK technique assigned"

    if row["event_4624"]:
        if (
            priority == "High"
            and row["is_remote_logon"]
            and row["failed_login_count"] >= 3
            and row["successful_login_count"] >= 1
        ):
            return "T1021 - Remote Services"

        return "Successful Logon - No ATT&CK technique assigned"

    if row["event_5140"]:
        return (
            "T1021.002 - SMB/Windows Admin Shares"
            if priority == "High"
            else "Network Share Access - Context Review Required"
        )

    if row["event_7045"]:
        return (
            "T1569.002 - Service Execution"
            if priority == "High"
            else "Service Creation - Context Review Required"
        )

    if row["event_4672"]:
        return "Privileged Logon Activity - Context Review Required"

    if row["event_4688"]:
        return "Process Creation - Context Review Required"

    return "Live Alert - Unclassified"

def recommend_response(priority, source_ip, row):
    if priority == "Low":
        return "retain_no_action", "Low-priority event retained for audit."

    if source_ip is None:
        return "escalate_review", "High-priority event has no actionable source IP."

    suspicious_auth = (
        row["failed_login_count"] >= SPRAY_MIN_ATTEMPTS
        or row["unique_users_targeted"] >= SPRAY_MIN_USERS
    )

    sensitive_event = row["event_5140"] or row["event_7045"]

    if suspicious_auth or sensitive_event:
        return (
            "containment_candidate",
            "Suspicious activity with an actionable source IP.",
        )

    return "escalate_review", "High-priority event requires analyst confirmation."

# 11. SCORE ONE ALERT
def score_alert(alert, source_alert_id, window_stats):
    event_id = get_event_id(alert)

    if event_id not in SUPPORTED_EVENTS:
        return None

    user = get_user(alert, event_id)

    # Remove machine-account and anonymous authentication noise.
    if event_id in (4624, 4625) and not is_real_user(user):
        return None

    row = build_feature_row(alert, window_stats)

    frame = pd.DataFrame([row], columns=feature_columns)
    scaled = scaler.transform(frame)

    raw_score = float(-model.decision_function(scaled)[0])
    anomaly = normalize_anomaly(raw_score)
    context = calculate_context(row)
    risk = calculate_risk(row, anomaly, context)
    priority = "High" if risk >= FINAL_RISK_THRESHOLD else "Low"
    
    # Event 7045 means a new Windows service was created, so it is treated as High
    if row["event_7045"] == 1:
       priority = "High"
       risk = max(risk, 0.70)

    source_ip = get_source_ip(alert)
    response_action, response_reason = recommend_response(priority, source_ip, row)

    timestamp = alert.get("@timestamp")
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    document = {
        "@timestamp": timestamp,
        "timestamp": timestamp,
        "host": get_host(alert),
        "host_ip": get_host_ip(alert),
        "user": user,
        "source_ip": source_ip,
        "event_id": event_id,
        "rule_level": row["rule_level"],
        "failed_login_count": row["failed_login_count"],
        "successful_login_count": row["successful_login_count"],
        "same_source_ip_attempts": row["same_source_ip_attempts"],
        "unique_users_targeted": row["unique_users_targeted"],
        "distinct_hosts_accessed": row["distinct_hosts_accessed"],
        "hour_of_day": row["hour_of_day"],
        "is_after_hours": row["is_after_hours"],
        "is_remote_logon": row["is_remote_logon"],
        "logon_type": row["logon_type"],
        "asset_criticality": row["asset_criticality"],
        "anomaly_score": round(anomaly, 4),
        "behavioral_context_score": round(context, 4),
        "risk_score": round(risk, 4),
        "priority_output": priority,
        "mitre_technique": map_mitre(row, priority),
        "response_action": response_action,
        "response_reason": response_reason,
        "source_alert_id": source_alert_id,
        "source_rule_description": safe_text(
            alert.get("rule", {}).get("description"),
            "No description",
        ),
    }

    for supported_id in SUPPORTED_EVENTS:
        document[f"event_{supported_id}"] = row[f"event_{supported_id}"]

    return document

# 12. MAIN LOOP
def run():
    seen_ids = load_seen_ids()

    log.info("Source index: %s", SOURCE_INDEX)
    log.info("Target index: %s", TARGET_INDEX)
    log.info("Risk threshold: %.2f", FINAL_RISK_THRESHOLD)
    log.info("Polling every %d seconds", POLL_SECONDS)
    log.info("Supported events: %s", SUPPORTED_EVENTS)

    while True:
        try:
            response = client.search(
                index=SOURCE_INDEX,
                body={
                    "size": 500,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "query": {
                        "range": {
                            "@timestamp": {
                                "gte": LOOKBACK_WINDOW,
                                "lte": "now",
                            }
                        }
                    },
                },
            )

            hits = response["hits"]["hits"]
            new_hits = [hit for hit in hits if hit["_id"] not in seen_ids]

            if not new_hits:
                log.info("No new alerts.")
                time.sleep(POLL_SECONDS)
                continue

            window_stats = build_window_stats(hits)
            actions = []
            unsupported = 0

            for hit in new_hits:
                event_id = get_event_id(hit["_source"])
                seen_ids.add(hit["_id"])

                if event_id not in SUPPORTED_EVENTS:
                    unsupported += 1
                    continue

                document = score_alert(hit["_source"], hit["_id"], window_stats)

                if document:
                    actions.append(
                        {
                            "_index": TARGET_INDEX,
                            "_source": document,
                        }
                    )

            if actions:
                success, failed_items = bulk(
                    client,
                    actions,
                    raise_on_error=False,
                )

                high_count = sum(
                    item["_source"]["priority_output"] == "High"
                    for item in actions
                )

                log.info(
                    "Indexed %d | High: %d | Low: %d | Unsupported: %d | Failed: %d",
                    success,
                    high_count,
                    len(actions) - high_count,
                    unsupported,
                    len(failed_items) if failed_items else 0,
                )
            else:
                log.info("No supported documents were indexed.")

            save_seen_ids(seen_ids)

        except KeyboardInterrupt:
            save_seen_ids(seen_ids)
            log.info("Stopped by user.")
            break

        except Exception as error:
            log.error("Live scorer error: %s", error)

        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    run()