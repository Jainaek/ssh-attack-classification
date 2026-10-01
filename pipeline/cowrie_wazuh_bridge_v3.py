import json
import os
import pickle
import logging
import argparse
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

ALERT_LOG = "/var/ossec/logs/cowrie_alerts.log"

# ── Attack type classification ─────────────────────────────────────────────────
COMMON_USERNAMES = {
    'root', 'admin', 'ubuntu', 'user', 'test', 'guest', 'oracle',
    'pi', 'vagrant', 'ansible', 'deploy', 'postgres', 'mysql',
    'ftpuser', 'www', 'nginx', 'apache', 'tomcat', 'hadoop'
}

MALWARE_COMMANDS = [
    'wget', 'curl', 'chmod +x', 'rm -rf', '/bin/sh', 'bash -i',
    'python -c', 'perl -e', 'nc ', 'ncat', 'tftp', 'ftp ',
    'base64 -d', 'echo ', '>/dev/', 'mkfifo', 'nohup'
]

def classify_attack_types(d):
    types = []

    login_failed = d['login_failed']
    login_success = d['login_success']
    commands = d['commands']
    downloads = d['downloads']
    lateral = d['lateral_movement']
    recon = d['recon']
    hits = d['hits']
    usernames = d['usernames']
    malware_cmds = d['malware_commands']
    duration = d['duration']

    # Reconnaissance — probing only, no login attempts
    if recon > 0 and login_failed == 0 and login_success == 0:
        types.append('Reconnaissance')

    # Brute Force — many failed logins, automated (short duration, high rate)
    if login_failed > 10 and login_success == 0:
        if duration < 5 or (hits / max(duration, 0.01)) > 10:
            types.append('Brute Force')

    # Dictionary Attack — failed logins using common usernames
    if login_failed > 0 and len(usernames & COMMON_USERNAMES) >= 3:
        types.append('Dictionary Attack')

    # Credential Stuffing — successful login after relatively few attempts
    if login_success > 0 and login_failed < 20:
        types.append('Credential Stuffing')

    # Post-Exploitation — commands run after successful login
    if login_success > 0 and commands > 0 and malware_cmds == 0:
        types.append('Post-Exploitation')

    # Malware Deployment — malware commands or file downloads
    if downloads > 0 or malware_cmds > 0:
        types.append('Malware Deployment')

    # Lateral Movement — direct-tcpip / port forwarding
    if lateral > 0:
        types.append('Lateral Movement')

    # Default if nothing matched
    if not types:
        if login_failed > 0:
            types.append('Brute Force')
        else:
            types.append('Reconnaissance')

    return types

# Dominant attack type priority order
PRIORITY = [
    'Malware Deployment',
    'Lateral Movement',
    'Post-Exploitation',
    'Credential Stuffing',
    'Dictionary Attack',
    'Brute Force',
    'Reconnaissance'
]

def get_dominant(types):
    for p in PRIORITY:
        if p in types:
            return p
    return types[0]

# ── Severity — composite of attack type sophistication + hit volume ────────────
#
# Base severity tier per attack type (1=Low, 2=Medium, 3=High, 4=Critical).
# Rationale:
#   Malware Deployment / Lateral Movement  → active system compromise (base: High)
#   Post-Exploitation / Credential Stuffing → post-access but contained (base: Medium)
#   Brute Force                            → active but noisy (base: Medium)
#   Dictionary Attack / Reconnaissance     → low sophistication (base: Low)
#
# Gradual escalation based on hit volume reflects attacker persistence:
#   > 300 hits → escalate 2 tiers (very persistent)
#   > 100 hits → escalate 1 tier  (persistent)
#   ≤ 100 hits → no escalation    (base tier only)
#
# This ensures alerts of the same attack type vary in severity based on
# session volume, producing a realistic distribution across all four levels.
#
ATTACK_BASE_TIER = {
    'Malware Deployment':  3,   # High  → Critical if persistent
    'Lateral Movement':    3,   # High  → Critical if persistent
    'Post-Exploitation':   2,   # Medium → High/Critical if persistent
    'Credential Stuffing': 2,   # Medium → High/Critical if persistent
    'Brute Force':         2,   # Medium → High/Critical if persistent
    'Dictionary Attack':   1,   # Low   → Medium/High if persistent
    'Reconnaissance':      2,   # Low   → Medium/High if persistent
}

SEV_LABELS_BOT = {
    1: ('BOT_LOW',       8),
    2: ('BOT_MEDIUM',   11),
    3: ('BOT_HIGH',     13),
    4: ('BOT_CRITICAL', 15),
}

SEV_LABELS_HUMAN = {
    1: ('HUMAN_LOW',      10),
    2: ('HUMAN_MEDIUM',   11),
    3: ('HUMAN_HIGH',     13),
    4: ('HUMAN_CRITICAL', 15),
}

def get_severity(classification, hits, dominant_attack_type):
    base = ATTACK_BASE_TIER.get(dominant_attack_type, 1)
    # Gradual escalation: very persistent attackers jump 2 tiers,
    # moderately persistent jump 1 tier, low-volume stay at base
    if hits > 300:
        base = min(base + 2, 4)
    elif hits > 100:
        base = min(base + 1, 4)
    labels = SEV_LABELS_BOT if classification == "BOT" else SEV_LABELS_HUMAN
    return labels[base]

# ── Load events ────────────────────────────────────────────────────────────────
def load_events(log_path):
    events = []
    if log_path.endswith('.json'):
        try:
            with open(log_path, 'r', errors='ignore') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except:
            pass
    # Try NDJSON
    with open(log_path, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except:
                continue
    return events

def load_kaggle_logs(json_dir):
    events = []
    for fname in sorted(os.listdir(json_dir)):
        fpath = os.path.join(json_dir, fname)
        with open(fpath, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except:
                    continue
    return events

# ── Main ───────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument('--log',    help='Path to JSON log file')
parser.add_argument('--kaggle', help='Path to Kaggle JSON log directory')
parser.add_argument('--model',  required=True, help='Path to ML model')
args = parser.parse_args()

with open(args.model, 'rb') as f:
    model = pickle.load(f)

if args.kaggle:
    print(f"Loading Kaggle logs from {args.kaggle}...")
    events = load_kaggle_logs(args.kaggle)
elif args.log:
    print(f"Loading log from {args.log}...")
    events = load_events(args.log)
else:
    print("ERROR: provide --log or --kaggle")
    exit(1)

print(f"Total events: {len(events)}")

# ── Extract features per IP ────────────────────────────────────────────────────
ip_data = defaultdict(lambda: {
    'hits': 0, 'timestamps': [], 'commands': 0,
    'login_failed': 0, 'login_success': 0, 'downloads': 0,
    'lateral_movement': 0, 'recon': 0, 'malware_commands': 0,
    'usernames': set(), 'raw_commands': [], 'duration': 0
})

for e in events:
    ip = e.get('src_ip') or e.get('peerIP')
    if not ip:
        continue
    eid = e.get('eventid', '')
    ip_data[ip]['hits'] += 1

    ts = e.get('timestamp')
    if ts:
        try:
            ip_data[ip]['timestamps'].append(datetime.fromisoformat(ts[:19]))
        except:
            pass

    if 'login.failed' in eid:
        ip_data[ip]['login_failed'] += 1
        if e.get('username'):
            ip_data[ip]['usernames'].add(e['username'].lower())
    if 'login.success' in eid:
        ip_data[ip]['login_success'] += 1
        if e.get('username'):
            ip_data[ip]['usernames'].add(e['username'].lower())
    if 'command.input' in eid or e.get('command') or e.get('input'):
        cmd = e.get('input') or e.get('command', '')
        ip_data[ip]['commands'] += 1
        ip_data[ip]['raw_commands'].append(cmd)
        if any(m in cmd.lower() for m in MALWARE_COMMANDS):
            ip_data[ip]['malware_commands'] += 1
    if 'file_download' in eid:
        ip_data[ip]['downloads'] += 1
    if 'direct-tcpip' in eid:
        ip_data[ip]['lateral_movement'] += 1
    if 'client.version' in eid or 'session.params' in eid:
        ip_data[ip]['recon'] += 1

print(f"Unique IPs: {len(ip_data)}")

# ── Classify and send alerts ───────────────────────────────────────────────────
bot_count = 0
human_count = 0
attack_type_counts = defaultdict(int)
severity_counts = defaultdict(int)

with open(ALERT_LOG, 'a') as log:
    for ip, d in ip_data.items():
        hits = d['hits']
        t = d['timestamps']
        duration = (max(t) - min(t)).total_seconds() / 60 if len(t) >= 2 else 0.01
        d['duration'] = duration
        intensity = d['commands'] / duration if duration > 0 else 0

        # ML classification — BOT or HUMAN
        pred = model.predict([[hits, duration, intensity]])[0]
        classification = "BOT" if pred == 1 else "HUMAN"

        if classification == "BOT":
            bot_count += 1
        else:
            human_count += 1

        # Attack type classification
        attack_types = classify_attack_types(d)
        dominant = get_dominant(attack_types)
        attack_type_counts[dominant] += 1

        # Severity: composite of attack sophistication + hit volume
        severity_label, severity_level = get_severity(classification, hits, dominant)
        severity_counts[severity_label] += 1

        alert = {
            "src_ip": ip,
            "classification": classification,
            "dominant_attack_type": dominant,
            "all_attack_types": attack_types,
            "severity": severity_label,
            "wazuh_level": severity_level,
            "total_hits": hits,
            "duration_mins": round(duration, 2),
            "intensity": round(intensity, 2),
            "login_failed": d['login_failed'],
            "login_success": d['login_success'],
            "downloads": d['downloads'],
            "lateral_movement": d['lateral_movement'],
            "recon": d['recon'],
            "malware_commands": d['malware_commands'],
            "commands_run": d['raw_commands'][:20],
            "usernames_tried": list(d['usernames'])[:10]
        }

        log.write(f"COWRIE: {json.dumps(alert, separators=(',', ':'))}\n")
        logging.info(
            f"{classification} | {dominant} | {severity_label} | {ip} | hits={hits}"
        )

print(f"\nDone. BOT: {bot_count} | HUMAN: {human_count}")
print(f"\nAttack type breakdown:")
for k, v in sorted(attack_type_counts.items(), key=lambda x: -x[1]):
    print(f"  {v:>6}  {k}")
print(f"\nSeverity breakdown:")
for k, v in sorted(severity_counts.items(), key=lambda x: -x[1]):
    print(f"  {v:>6}  {k}")
print(f"\nAlerts written to {ALERT_LOG}")
