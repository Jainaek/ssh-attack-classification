import json
import pickle
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from datetime import datetime

# ── HELPER: extract features from a JSON log file/list ────────────────────────
def extract_features(events):
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
        if e.get("command") or e.get("input") or "command" in e.get("eventid", ""):
            ip_data[ip]["commands"] += 1

    rows = []
    for ip, d in ip_data.items():
        hits = d["hits"]
        timestamps = d["timestamps"]
        duration = (max(timestamps) - min(timestamps)).total_seconds() / 60.0 if len(timestamps) >= 2 else 0.0
        intensity = d["commands"] / duration if duration > 0 else 0.0
        rows.append({"ip": ip, "total_hits": hits, "duration_mins": duration, "intensity": intensity})
    return pd.DataFrame(rows)

# ── 1. Load TRAINING data (your original dataset) ─────────────────────────────
print("Loading training data...")
train_events = []
with open("/home/wazuh-user/recovered_data.json", "r", errors="ignore") as f:
    train_events = json.load(f)

print(f"Training events: {len(train_events)}")
train_df = extract_features(train_events)

# Label: BOT = top 39% by hits (matches your known 39% BOT distribution)
threshold = train_df["total_hits"].quantile(0.61)
train_df["label"] = (train_df["total_hits"] > threshold).astype(int)
print(f"Training IPs: {len(train_df)} | BOT: {train_df['label'].sum()} | HUMAN: {(train_df['label']==0).sum()}")

# ── 2. Train model ────────────────────────────────────────────────────────────
X_train = train_df[["total_hits", "duration_mins", "intensity"]].values
y_train = train_df["label"].values

print("\nTraining Random Forest...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save new model
with open("/home/wazuh-user/honeypot_model_compat.pkl", "wb") as f:
    pickle.dump(model, f)
print("Model saved.")

# ── 3. Load TEST data (Kaggle JSON logs — never seen by model) ────────────────
print("\nLoading Kaggle test data...")
JSON_DIR = "/media/sf_shared/archive/json_log/json_log/"
test_events = []

for fname in sorted(os.listdir(JSON_DIR)):
    fpath = os.path.join(JSON_DIR, fname)
    with open(fpath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                test_events.append(json.loads(line))
            except:
                continue

print(f"Test events: {len(test_events)}")
test_df = extract_features(test_events)
print(f"Test unique IPs: {len(test_df)}")

# Label test set using same percentile logic
test_threshold = test_df["total_hits"].quantile(0.61)
test_df["label"] = (test_df["total_hits"] > test_threshold).astype(int)
print(f"Test BOT: {test_df['label'].sum()} | HUMAN: {(test_df['label']==0).sum()}")

# ── 4. Evaluate ───────────────────────────────────────────────────────────────
X_test = test_df[["total_hits", "duration_mins", "intensity"]].values
y_true = test_df["label"].values
y_pred = model.predict(X_test)

print("\n===== CLASSIFICATION REPORT (Unseen Kaggle Data) =====")
report = classification_report(y_true, y_pred, target_names=["HUMAN", "BOT"])
print(report)

print("===== CONFUSION MATRIX =====")
cm = confusion_matrix(y_true, y_pred)
print(f"                 Predicted HUMAN  Predicted BOT")
print(f"Actual HUMAN     {cm[0][0]:<17} {cm[0][1]}")
print(f"Actual BOT       {cm[1][0]:<17} {cm[1][1]}")

# ── 5. Save results ───────────────────────────────────────────────────────────
results = {
    "training_ips": len(train_df),
    "test_ips": len(test_df),
    "test_events": len(test_events),
    "classification_report": classification_report(y_true, y_pred, target_names=["HUMAN", "BOT"], output_dict=True),
    "confusion_matrix": cm.tolist()
}
with open("/media/sf_shared/model_evaluation_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("\nResults saved to /media/sf_shared/model_evaluation_results.json")