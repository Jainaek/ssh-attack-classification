import json
import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE

# ── 1. LOAD YOUR TRAINING DATA ─────────────────────────────────────────────
# Load the ground truth labels
labels_df = pd.read_csv('ground_truth_labels.csv')

# Load your events JSON file
# Replace 'recovered_data.json' with whatever your training events file is called
with open('recovered_data.json', 'r') as f:
    raw_events = json.load(f)

# ── 2. AGGREGATE EVENTS BY IP ──────────────────────────────────────────────
ip_profiles = {}

for event in raw_events:
    ip = event.get('src_ip')
    if not ip:
        continue
    if ip not in ip_profiles:
        ip_profiles[ip] = {
            'total_hits': 0,
            'timestamps': [],
            'commands': 0
        }
    ip_profiles[ip]['total_hits'] += 1
    if event.get('timestamp'):
        ip_profiles[ip]['timestamps'].append(event['timestamp'])
    if event.get('eventid') == 'cowrie.command.input':
        ip_profiles[ip]['commands'] += 1

# ── 3. COMPUTE FEATURES ────────────────────────────────────────────────────
records = []

for ip, profile in ip_profiles.items():
    total_hits = profile['total_hits']
    timestamps = sorted(profile['timestamps'])

    if len(timestamps) >= 2:
        from datetime import datetime
        fmt = '%Y-%m-%dT%H:%M:%S.%f'
        try:
            t1 = datetime.strptime(timestamps[0][:26], fmt)
            t2 = datetime.strptime(timestamps[-1][:26], fmt)
            duration_mins = max((t2 - t1).total_seconds() / 60, 0.001)
        except:
            duration_mins = 0.001
    else:
        duration_mins = 0.001

    intensity = profile['commands'] / duration_mins

    records.append({
        'ip': ip,
        'total_hits': total_hits,
        'duration_mins': duration_mins,
        'intensity': intensity
    })

features_df = pd.DataFrame(records)

# ── 4. MERGE WITH LABELS ───────────────────────────────────────────────────
merged = features_df.merge(labels_df, on='ip', how='inner')
print(f"Matched IPs: {len(merged)}")
print(f"Label distribution before SMOTE:")
print(merged['label'].value_counts())

X = merged[['total_hits', 'duration_mins', 'intensity']].values
y = merged['label'].values

# ── 5. SPLIT FIRST (before SMOTE) ─────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y  # ensures both splits have proportional BOT/HUMAN
)

print(f"\nTraining set size: {len(X_train)}")
print(f"Test set size: {len(X_test)}")
print(f"HUMAN in training: {list(y_train).count('HUMAN')}")
print(f"HUMAN in test: {list(y_test).count('HUMAN')}")

# ── 6. APPLY SMOTE TO TRAINING SET ONLY ───────────────────────────────────
smote = SMOTE(random_state=42)
X_train_smote, y_train_smote = smote.fit_resample(X_train, y_train)

print(f"\nAfter SMOTE:")
print(f"Training set size: {len(X_train_smote)}")
unique, counts = np.unique(y_train_smote, return_counts=True)
print(dict(zip(unique, counts)))

# ── 7. TRAIN MODEL ─────────────────────────────────────────────────────────
model = RandomForestClassifier(
    class_weight='balanced',
    random_state=42,
    n_estimators=100
)
model.fit(X_train_smote, y_train_smote)

# ── 8. EVALUATE ON UNTOUCHED TEST SET ─────────────────────────────────────
y_pred = model.predict(X_test)

print("\n── CLASSIFICATION REPORT ──────────────────────────────")
print(classification_report(y_test, y_pred))

# ── 9. SAVE THE NEW MODEL ──────────────────────────────────────────────────
with open('rf_model_smote.pkl', 'wb') as f:
    pickle.dump(model, f)

print("New model saved as rf_model_smote.pkl")