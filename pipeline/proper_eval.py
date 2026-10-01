import json, pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from datetime import datetime

# Load data
with open('/home/wazuh-user/recovered_data.json') as f:
    events = json.load(f)

# Extract features per IP
ip_data = {}
for e in events:
    ip = e.get('src_ip')
    if not ip:
        continue
    if ip not in ip_data:
        ip_data[ip] = {'hits': 0, 'timestamps': [], 'commands': 0}
    ip_data[ip]['hits'] += 1
    ts = e.get('timestamp')
    if ts:
        try:
            ip_data[ip]['timestamps'].append(datetime.fromisoformat(ts[:19]))
        except:
            pass
    if e.get('command') or 'command' in e.get('eventid', ''):
        ip_data[ip]['commands'] += 1

rows = []
for ip, d in ip_data.items():
    hits = d['hits']
    t = d['timestamps']
    duration = (max(t) - min(t)).total_seconds() / 60 if len(t) >= 2 else 0
    intensity = d['commands'] / duration if duration > 0 else 0
    rows.append({'total_hits': hits, 'duration_mins': duration, 'intensity': intensity})

df = pd.DataFrame(rows)
threshold = df['total_hits'].quantile(0.61)
df['label'] = (df['total_hits'] > threshold).astype(int)

print(f"Total IPs: {len(df)}")
print(f"BOT: {df['label'].sum()} | HUMAN: {(df['label']==0).sum()}")

# 80/20 split - model never sees test data
X = df[['total_hits', 'duration_mins', 'intensity']].values
y = df['label'].values
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"\nTraining on {len(X_train)} IPs, testing on {len(X_test)} IPs")

# Train
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save updated model
with open('/home/wazuh-user/honeypot_model_compat.pkl', 'wb') as f:
    pickle.dump(model, f)
print("Model saved.")

# Evaluate on unseen 20%
y_pred = model.predict(X_test)

print("\n===== CLASSIFICATION REPORT (Unseen 20% Test Set) =====")
print(classification_report(y_test, y_pred, target_names=['HUMAN', 'BOT']))

print("===== CONFUSION MATRIX =====")
cm = confusion_matrix(y_test, y_pred)
print(f"                 Predicted HUMAN  Predicted BOT")
print(f"Actual HUMAN     {cm[0][0]:<17} {cm[0][1]}")
print(f"Actual BOT       {cm[1][0]:<17} {cm[1][1]}")

# Save results
results = {
    "total_ips": len(df),
    "train_size": len(X_train),
    "test_size": len(X_test),
    "classification_report": classification_report(y_test, y_pred, target_names=['HUMAN', 'BOT'], output_dict=True),
    "confusion_matrix": cm.tolist()
}
with open('/media/sf_shared/proper_eval_results.json', 'w') as f:
    json.dump(results, f, indent=2)

print("\nResults saved to /media/sf_shared/proper_eval_results.json")