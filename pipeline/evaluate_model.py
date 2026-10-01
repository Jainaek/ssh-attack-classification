import json
import pickle
import os
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from datetime import datetime

# ── 1. Load model ──────────────────────────────────────────────────────────────
MODEL_PATH = "/home/wazuh-user/honeypot_model_compat.pkl"
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# ── 2. Load all Kaggle JSON logs ───────────────────────────────────────────────
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
            except json.JSONDecodeError:
                continue

print(f"Total events loaded: {len(events)}")

# ── 3. Extract features per IP (same logic as your bridge script) ──────────────
ip_data = {}

for e in events:
    ip = e.get("src_ip") or e.get("peerIP")
    if not ip:
        continue
    if ip not in ip_data:
        ip_data[ip] = {"hits": 0, "timestamps": [], "commands": 0}
    ip_data[ip]["hits"] += 1
    ts = e.get("timestamp")
    if ts:
        try:
            ip_data[ip]["timestamps"].append(datetime.fromisoformat(ts[:19]))
        except:
            pass
    if e.get("input") or e.get("eventid", "").endswith("command"):
        ip_data[ip]["commands"] += 1

rows = []
for ip, d in ip_data.items():
    hits = d["hits"]
    timestamps = d["timestamps"]
    if len(timestamps) >= 2:
        duration = (max(timestamps) - min(timestamps)).total_seconds() / 60.0
    else:
        duration = 0.0
    intensity = d["commands"] / duration if duration > 0 else 0.0
    rows.append({"ip": ip, "total_hits": hits, "duration_mins": duration, "intensity": intensity})

df = pd.DataFrame(rows)
print(f"Unique IPs: {len(df)}")
print(df[["total_hits", "duration_mins", "intensity"]].describe())

# ── 4. Auto-label for evaluation (percentile-based, same as your training) ─────
# BOT = high hits with low duration (automated), HUMAN = interactive sessions
# Use hit count: top 40% = BOT, rest = HUMAN (mirrors your training distribution)
threshold = df["total_hits"].quantile(0.60)
df["true_label"] = df["total_hits"].apply(lambda x: 1 if x > threshold else 0)
# 1 = BOT, 0 = HUMAN

print(f"\nLabel distribution:")
print(df["true_label"].value_counts())

# ── 5. Run model predictions ───────────────────────────────────────────────────
X = df[["total_hits", "duration_mins", "intensity"]].values
y_true = df["true_label"].values
y_pred = model.predict(X)

# ── 6. Print results ───────────────────────────────────────────────────────────
print("\n===== CLASSIFICATION REPORT =====")
print(classification_report(y_true, y_pred, target_names=["HUMAN", "BOT"]))

print("===== CONFUSION MATRIX =====")
cm = confusion_matrix(y_true, y_pred)
print(f"                Predicted HUMAN  Predicted BOT")
print(f"Actual HUMAN    {cm[0][0]:<17} {cm[0][1]}")
print(f"Actual BOT      {cm[1][0]:<17} {cm[1][1]}")

# ── 7. Save results to file ────────────────────────────────────────────────────
output = {
    "total_events": len(events),
    "unique_ips": len(df),
    "classification_report": classification_report(y_true, y_pred, target_names=["HUMAN", "BOT"], output_dict=True),
    "confusion_matrix": cm.tolist()
}

with open("/media/sf_shared/model_evaluation_results.json", "w") as f:
    json.dump(output, f, indent=2)

print("\nResults saved to /media/sf_shared/model_evaluation_results.json")