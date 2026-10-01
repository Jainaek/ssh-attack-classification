import json
import os
import pickle
import logging
import socket
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

MODEL_PATH = "/home/wazuh-user/honeypot_model_compat.pkl"
JSON_DIR = "/media/sf_shared/archive/json_log/json_log/"
ALERT_LOG = "/var/ossec/logs/cowrie_alerts.log"
SYSLOG_PATH = "/var/ossec/logs/cowrie_alerts.log"

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# Load all Kaggle events
print("Loading Kaggle JSON logs...")
events = []
for fname in sorted(os.listdir(JSON_DIR)):
    fpath = os.path.join(JSON_DIR, fname)
    with open(fpath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except:
                continue

print(f"Total events: {len(events)}")

# Extract features per IP
ip_data = defaultdict(lambda: {
    'hits': 0,
    'timestamps': [],
    'commands': 0,
    'login_failed': 0,
    'login_success': 0,
    'downloads': 0,
    'lateral_movement': 0,
    'recon': 0,
    'event_types': set()
})

for e in events:
    ip = e.get('src_ip') or e.get('peerIP')
    if not ip:
        continue
    eid = e.get('eventid', '')
    ip_data[ip]['hits'] += 1
    ip_data[ip]['event_types'].add(eid)

    ts = e.get('timestamp')
    if ts:
        try:
            ip_data[ip]['timestamps'].append(datetime.fromisoformat(ts[:19]))
        except:
            pass

    if 'command.input' in eid or e.get('command') or e.get('input'):
        ip_data[ip]['commands'] += 1
    if 'login.failed' in eid:
        ip_data[ip]['login_failed'] += 1
    if 'login.success' in eid:
        ip_data[ip]['login_success'] += 1
    if 'file_download' in eid:
        ip_data[ip]['downloads'] += 1
    if 'direct-tcpip' in eid:
        ip_data[ip]['lateral_movement'] += 1
    if 'client.version' in eid or 'session.params' in eid:
        ip_data[ip]['recon'] += 1

print(f"Unique IPs: {len(ip_data)}")

# Determine severity tier
def get_severity(classification, hits):
    if classification == "BOT":
        if hits > 50:
            return "BOT_CRITICAL", 15
        elif hits >= 37:
            return "BOT_HIGH", 13
        elif hits >= 21:
            return "BOT_MEDIUM", 11
        else:
            return "BOT_LOW", 8
    else:
        if hits > 50:
            return "HUMAN_CRITICAL", 15
        elif hits >= 21:
            return "HUMAN_HIGH", 13
        else:
            return "HUMAN_LOW", 10

# Classify and alert
bot_count = 0
human_count = 0

with open(ALERT_LOG, "a") as log:
    for ip, d in ip_data.items():
        hits = d['hits']
        t = d['timestamps']
        duration = (max(t) - min(t)).total_seconds() / 60 if len(t) >= 2 else 0.01
        intensity = d['commands'] / duration if duration > 0 else 0

        features = [[hits, duration, intensity]]
        pred = model.predict(features)[0]
        classification = "BOT" if pred == 1 else "HUMAN"

        if classification == "BOT":
            bot_count += 1
        else:
            human_count += 1

        severity_label, severity_level = get_severity(classification, hits)

        alert = {
            "src_ip": ip,
            "classification": classification,
            "severity": severity_label,
            "total_hits": hits,
            "duration_mins": round(duration, 2),
            "intensity": round(intensity, 2),
            "login_failed": d['login_failed'],
            "login_success": d['login_success'],
            "downloads": d['downloads'],
            "lateral_movement": d['lateral_movement'],
            "recon": d['recon'],
            "attack_types": list(d['event_types']),
            "wazuh_level": severity_level
        }

        log.write(f"COWRIE: {json.dumps(alert)}\n")
        logging.info(f"{classification} | {severity_label} | {ip} | hits={hits}")

print(f"\nDone. BOT: {bot_count} | HUMAN: {human_count}")
print(f"Alerts written to {ALERT_LOG}")