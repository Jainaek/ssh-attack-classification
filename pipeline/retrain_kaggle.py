import json
import pickle
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from datetime import datetime
from collections import defaultdict

def extract_features(events):
    ip_data = defaultdict(lambda: {
        'hits': 0,
        'timestamps': [],
        'commands': 0,
        'login_attempts': 0,
        'login_success': 0,
        'downloads': 0
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

        if 'command' in eid or e.get('command') or e.get('input'):
            ip_data[ip]['commands'] += 1
        if 'login.failed' in eid:
            ip_data[ip]['login_attempts'] += 1
        if 'login.success' in eid:
            ip_data[ip]['login_success'] += 1
        if 'download' in eid:
            ip_data[ip]['downloads'] += 1

    rows = []
    for ip, d in ip_data.items():
        hits = d['hits']
        t = d['timestamps']
        duration = (max(t) - min(t)).total_seconds() / 60 if len(t) >= 2 else 0.01
        intensity = d['commands'] / duration if duration > 0 else 0
        rows.append({
            'ip': ip,
            'total_hits': hits,
            'duration_mins': duration,
            'intensity': intensity,
            'login_attempts': d['login_attempts'],
            'login_success': d['login_success'],
            'downloads': d['downloads']
        })
    return pd.DataFrame(rows)

def label_ip(row):
    if row['login_success'] > 0 and row['intensity'] > 0:
        return 0  # HUMAN — logged in and ran commands interactively
    if row['total_hits'] > 50 and row['duration_mins'] < 5:
        return 1  # BOT — high volume, very short window
    if row['intensity'] > 10:
        return 1  # BOT — too many commands per minute to be human
    if row['downloads'] > 0 and row['login_success'] == 0:
        return 1  # BOT — attempted download without logging in
    if row['total_hits'] <= 5:
        return 0  # HUMAN — low hit count, exploratory
    return 1

# ── Load Kaggle JSON logs ──────────────────────────────────────────────────────
print("Loading Kaggle JSON logs...")
JSON_DIR = "/media/sf_shared/archive/json_log/json_log/"
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

df = extract_features(events)
print(f"Unique IPs: {len(df)}")

# Apply behavioural labelling
df['label'] = df.apply(label_ip, axis=1)
print(f"BOT: {df['label'].sum()} | HUMAN: {(df['label']==0).sum()}")
print(f"Event type breakdown:")
print(f"  IPs with login success: {(df['login_success']>0).sum()}")
print(f"  IPs with commands: {(df['intensity']>0).sum()}")
print(f"  IPs with downloads: {(df['downloads']>0).sum()}")

# ── Train/test split ───────────────────────────────────────────────────────────
X = df[['total_hits', 'duration_mins', 'intensity']].values
y = df['label'].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nTraining on {len(X_train)} IPs, testing on {len(X_test)} IPs")

# ── Train model ────────────────────────────────────────────────────────────────
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save model
with open('/home/wazuh-user/honeypot_model_compat.pkl', 'wb') as f:
    pickle.dump(model, f)
print("Model saved to /home/wazuh-user/honeypot_model_compat.pkl")

# ── Evaluate ───────────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)

print("\n===== CLASSIFICATION REPORT =====")
report = classification_report(y_test, y_pred, target_names=['HUMAN', 'BOT'])
print(report)

print("===== CONFUSION MATRIX =====")
cm = confusion_matrix(y_test, y_pred)
print(f"                 Predicted HUMAN  Predicted BOT")
print(f"Actual HUMAN     {cm[0][0]:<17} {cm[0][1]}")
print(f"Actual BOT       {cm[1][0]:<17} {cm[1][1]}")

# ── Save results ───────────────────────────────────────────────────────────────
results = {
    "total_events": len(events),
    "unique_ips": len(df),
    "bot_count": int(df['label'].sum()),
    "human_count": int((df['label']==0).sum()),
    "train_size": len(X_train),
    "test_size": len(X_test),
    "classification_report": classification_report(
        y_test, y_pred, target_names=['HUMAN', 'BOT'], output_dict=True
    ),
    "confusion_matrix": cm.tolist()
}
with open('/media/sf_shared/kaggle_eval_results.json', 'w') as f:
    json.dump(results, f, indent=2)

print("\nResults saved to /media/sf_shared/kaggle_eval_results.json")