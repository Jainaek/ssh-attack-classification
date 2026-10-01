"""
Cowrie Honeypot — K-Means Clustering Pipeline
==============================================
Aggregates raw honeypot tables into per-IP behavioural profiles,
clusters them with K-Means, interprets clusters, and exports
one structured alert JSON per attacker.

Input files (drop in same directory or set paths below):
  - sessions.csv
  - auth.csv
  - downloads.csv

Output:
  - attacker_profiles.csv   — feature table (one row per IP)
  - attacker_alerts.json    — one structured alert per IP
  - cluster_summary.csv     — centroid interpretation table
  - kmeans_model.pkl        — saved model for reuse
"""

import pandas as pd
import numpy as np
import json
import pickle
import warnings
from datetime import datetime
from pathlib import Path

from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.decomposition import PCA

warnings.filterwarnings("ignore")

# ── 0. CONFIG ────────────────────────────────────────────────────────────────

DATA_DIR   = Path(".")          # change if CSVs live elsewhere
OUTPUT_DIR = Path(".")
N_CLUSTERS = 3                  # tuned below; override if you want a fixed k
RANDOM_STATE = 42

# ── 1. LOAD DATA ─────────────────────────────────────────────────────────────

print("=" * 60)
print("  COWRIE HONEYPOT — K-MEANS PIPELINE")
print("=" * 60)
print("\n[1] Loading raw tables …")

sessions  = pd.read_csv(DATA_DIR / "sessions.csv",  parse_dates=["starttime", "endtime"])
auth      = pd.read_csv(DATA_DIR / "auth.csv",       parse_dates=["timestamp"])
downloads = pd.read_csv(DATA_DIR / "downloads.csv",  parse_dates=["timestamp"])

print(f"    sessions  : {len(sessions):,} rows  |  {sessions['ip'].nunique():,} unique IPs")
print(f"    auth      : {len(auth):,} rows")
print(f"    downloads : {len(downloads):,} rows")

# ── 2. FEATURE ENGINEERING ───────────────────────────────────────────────────

print("\n[2] Engineering per-IP features …")

# --- 2a. Session-level features ---
# Duration: difference in seconds between starttime and endtime
sessions["duration_s"] = (
    sessions["endtime"] - sessions["starttime"]
).dt.total_seconds().clip(lower=0)

# Aggregate per IP
sess_agg = (
    sessions.groupby("ip")
    .agg(
        total_sessions    = ("id",         "count"),
        total_duration_s  = ("duration_s", "sum"),
        mean_duration_s   = ("duration_s", "mean"),
        unique_sensors    = ("sensor",     "nunique"),
        has_client_info   = ("client",     lambda x: int(x.notna().any())),
        first_seen        = ("starttime",  "min"),
        last_seen         = ("starttime",  "max"),
    )
    .reset_index()
)

# Campaign span: seconds between first and last session from this IP
sess_agg["campaign_span_s"] = (
    sess_agg["last_seen"] - sess_agg["first_seen"]
).dt.total_seconds().clip(lower=0)

# --- 2b. Auth features (join session → IP via auth.session = sessions.id) ---
auth_with_ip = auth.merge(
    sessions[["id", "ip"]].rename(columns={"id": "session"}),
    on="session", how="left"
).dropna(subset=["ip"])

auth_agg = (
    auth_with_ip.groupby("ip")
    .agg(
        total_auth_attempts = ("id",       "count"),
        successful_logins   = ("success",  "sum"),
        unique_usernames    = ("username", "nunique"),
        unique_passwords    = ("password", "nunique"),
    )
    .reset_index()
)
auth_agg["success_rate"] = (
    auth_agg["successful_logins"] / auth_agg["total_auth_attempts"]
).fillna(0)

# --- 2c. Download features ---
dl_with_ip = downloads.merge(
    sessions[["id", "ip"]].rename(columns={"id": "session"}),
    on="session", how="left"
).dropna(subset=["ip"])

dl_agg = (
    dl_with_ip.groupby("ip")
    .agg(
        download_count  = ("id",  "count"),
        unique_urls     = ("url", "nunique"),
    )
    .reset_index()
)

# --- 2d. Merge everything ---
profiles = (
    sess_agg
    .merge(auth_agg, on="ip", how="left")
    .merge(dl_agg,   on="ip", how="left")
)

# Fill NaN for IPs with no auth or download records
fill_cols = [
    "total_auth_attempts", "successful_logins", "unique_usernames",
    "unique_passwords", "success_rate", "download_count", "unique_urls"
]
profiles[fill_cols] = profiles[fill_cols].fillna(0)

# --- 2e. Derived intensity metric ---
# Events per second of campaign span (proxy for automation speed)
profiles["auth_intensity"] = np.where(
    profiles["campaign_span_s"] > 0,
    profiles["total_auth_attempts"] / profiles["campaign_span_s"],
    profiles["total_auth_attempts"]   # whole campaign in one instant
)

print(f"    Profiles built: {len(profiles):,} unique IPs")
print(f"    Features used:")
feature_cols = [
    "total_sessions",
    "total_duration_s",
    "mean_duration_s",
    "campaign_span_s",
    "total_auth_attempts",
    "successful_logins",
    "unique_usernames",
    "unique_passwords",
    "success_rate",
    "download_count",
    "unique_urls",
    "auth_intensity",
    "has_client_info",
]
for c in feature_cols:
    print(f"      • {c}")

# ── 3. SCALE ─────────────────────────────────────────────────────────────────

print("\n[3] Imputing missing values and scaling features …")
from sklearn.impute import SimpleImputer

X = profiles[feature_cols].values

# Impute any NaN values with column median before scaling
imputer = SimpleImputer(strategy="median")
X = imputer.fit_transform(X)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ── 4. CHOOSE OPTIMAL k (elbow + silhouette) ─────────────────────────────────

print("\n[4] Selecting optimal k (2 – 6) …")
k_range   = range(2, 7)
inertias  = []
sil_scores = []

for k in k_range:
    km = KMeans(n_clusters=k, random_state=RANDOM_STATE, n_init=10)
    labels = km.fit_predict(X_scaled)
    inertias.append(km.inertia_)
    sil_scores.append(silhouette_score(X_scaled, labels))
    print(f"    k={k}  inertia={km.inertia_:,.0f}  silhouette={sil_scores[-1]:.4f}")

best_k = k_range.start + int(np.argmax(sil_scores))
print(f"\n    ✓ Best k by silhouette: {best_k}  (score={max(sil_scores):.4f})")
N_CLUSTERS = best_k

# ── 5. TRAIN FINAL MODEL ─────────────────────────────────────────────────────

print(f"\n[5] Training K-Means with k={N_CLUSTERS} …")
kmeans = KMeans(n_clusters=N_CLUSTERS, random_state=RANDOM_STATE, n_init=20)
profiles["cluster"] = kmeans.fit_predict(X_scaled)

final_sil = silhouette_score(X_scaled, profiles["cluster"])
print(f"    Final silhouette score: {final_sil:.4f}")

# ── 6. INTERPRET CLUSTERS ────────────────────────────────────────────────────

print("\n[6] Interpreting clusters …")

cluster_summary = profiles.groupby("cluster")[feature_cols].mean().round(3)
cluster_summary["n_ips"] = profiles.groupby("cluster")["ip"].count()

# Rule-based interpretation of cluster behaviour
def interpret_cluster(row):
    """
    Classify each IP as BOT or HUMAN to match existing Wazuh rules.

    BOT  — high-speed automated activity (intensity >= 2.0/sec)
           or near-zero auth (passive scanners with no credentials)
    HUMAN — slow, deliberate activity: low intensity, long sessions,
            file downloads, or targeted credential use
    """
    intensity      = row["auth_intensity"]
    has_downloads  = row["download_count"] > 1
    near_zero_auth = row["total_auth_attempts"] < 1
    long_session   = row["mean_duration_s"] > 60

    # High-speed automated spraying or passive bot scanning
    if intensity >= 2.0 or near_zero_auth:
        return "BOT"

    # Slow, deliberate, downloads malware or long dwell time
    if has_downloads or long_session or intensity < 0.5:
        return "HUMAN"

    # Moderate speed — still automated
    return "BOT"

cluster_summary["label"] = cluster_summary.apply(interpret_cluster, axis=1)

print("\n  Cluster Summary:")
print(cluster_summary[["n_ips", "label", "total_auth_attempts",
                         "auth_intensity", "mean_duration_s",
                         "download_count", "success_rate"]].to_string())

# Map labels back to profiles
label_map = cluster_summary["label"].to_dict()
profiles["behaviour_label"] = profiles["cluster"].map(label_map)

# ── 7. ATTACK TYPE CLASSIFICATION (rule-based) ───────────────────────────────

print("\n[7] Assigning attack types …")

def classify_attack(row):
    if row["download_count"] > 0:
        return "Malware Deployment"
    elif row["successful_logins"] > 0 and row["unique_usernames"] < 5:
        return "Credential Stuffing"
    elif row["unique_usernames"] > 50:
        return "Dictionary Attack"
    elif row["total_auth_attempts"] > 500:
        return "Brute Force"
    elif row["total_sessions"] > 10 and row["total_auth_attempts"] < 10:
        return "Reconnaissance"
    else:
        return "Brute Force"

profiles["attack_type"] = profiles.apply(classify_attack, axis=1)

# ── 8. SEVERITY SCORING ──────────────────────────────────────────────────────

print("[8] Scoring severity …")

ATTACK_TYPE_WEIGHT = {
    "Malware Deployment":  5,
    "Lateral Movement":    4,
    "Post-Exploitation":   4,
    "Credential Stuffing": 3,
    "Dictionary Attack":   2,
    "Brute Force":         2,
    "Reconnaissance":      1,
}

BEHAVIOUR_WEIGHT = {
    "HUMAN_LIKE":     3,
    "BRUTEFORCE_BOT": 2,
    "SCANNER_BOT":    1,
}

profiles["severity_score"] = (
    profiles["attack_type"].map(ATTACK_TYPE_WEIGHT).fillna(2) +
    profiles["behaviour_label"].map(BEHAVIOUR_WEIGHT).fillna(1) +
    np.log1p(profiles["total_auth_attempts"]) * 0.3 +
    (profiles["download_count"] > 0).astype(int) * 2
).round(2)

def severity_tier(score):
    if score >= 9:  return "CRITICAL"
    if score >= 6:  return "HIGH"
    if score >= 3:  return "MEDIUM"
    return "LOW"

profiles["severity_tier"] = profiles["severity_score"].apply(severity_tier)
profiles["final_label"] = profiles["behaviour_label"] + "_" + profiles["severity_tier"]

tier_counts = profiles["severity_tier"].value_counts()
print(f"    CRITICAL : {tier_counts.get('CRITICAL', 0)}")
print(f"    HIGH     : {tier_counts.get('HIGH', 0)}")
print(f"    MEDIUM   : {tier_counts.get('MEDIUM', 0)}")
print(f"    LOW      : {tier_counts.get('LOW', 0)}")

# ── 9. EXPORT PROFILES CSV ───────────────────────────────────────────────────

print("\n[9] Exporting attacker_profiles.csv …")
export_cols = [
    "ip", "cluster", "behaviour_label", "attack_type",
    "severity_score", "severity_tier", "final_label",
    "total_sessions", "campaign_span_s", "mean_duration_s",
    "total_auth_attempts", "successful_logins", "unique_usernames",
    "unique_passwords", "success_rate", "download_count",
    "unique_urls", "auth_intensity",
]
profiles[export_cols].to_csv(OUTPUT_DIR / "attacker_profiles.csv", index=False)
print(f"    Saved {len(profiles):,} rows → attacker_profiles.csv")

# ── 10. EXPORT ALERT LOG ─────────────────────────────────────────────────────
# Format matches existing cowrie_decoders.xml — prematch "COWRIE: "
# Fields: classification, dominant_attack_type, severity

print("[10] Generating attacker_alerts.log …")

with open(OUTPUT_DIR / "attacker_alerts.log", "w") as f:
    for _, row in profiles.iterrows():
        # Format matches cowrie_decoders.xml regex exactly:
        # "classification":"(\S+)","dominant_attack_type":"(\.+)"
        b  = row['behaviour_label']
        at = row['attack_type']
        sv = row['severity_tier']
        ip = row['ip']
        fl = row['final_label']
        ta = int(row['total_auth_attempts'])
        sl = int(row['successful_logins'])
        dc = int(row['download_count'])
        line = (f'COWRIE: "source_ip":"{ip}",'
                f'"classification":"{b}",'
                f'"dominant_attack_type":"{at}",'
                f'"all_attack":"{at}",'
                f'"severity":"{sv}",'
                f'"final_label":"{fl}",'
                f'"total_auth_attempts":"{ta}",'
                f'"successful_logins":"{sl}",'
                f'"download_count":"{dc}"')
        f.write(line + "\n")

print(f"    Saved {len(profiles):,} alerts → attacker_alerts.log")

# ── 11. EXPORT CLUSTER SUMMARY ───────────────────────────────────────────────

cluster_summary.to_csv(OUTPUT_DIR / "cluster_summary.csv")
print(f"    Saved cluster interpretation → cluster_summary.csv")

# ── 12. SAVE MODEL + SCALER ──────────────────────────────────────────────────

with open(OUTPUT_DIR / "kmeans_model.pkl", "wb") as f:
    pickle.dump({"model": kmeans, "scaler": scaler, "imputer": imputer, "features": feature_cols,
                 "label_map": label_map}, f)
print(f"    Saved model + scaler → kmeans_model.pkl")

# ── 13. FINAL SUMMARY ────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("  PIPELINE COMPLETE")
print("=" * 60)
print(f"\n  Raw events   : {len(sessions) + len(auth) + len(downloads):,}")
print(f"  IP profiles  : {len(profiles):,}  ({(1 - len(profiles)/(len(sessions)+len(auth)+len(downloads)))*100:.1f}% reduction)")
print(f"  Clusters     : {N_CLUSTERS}")
print(f"  Silhouette   : {final_sil:.4f}")
print()
print("  Behaviour distribution:")
for label, count in profiles["behaviour_label"].value_counts().items():
    pct = count / len(profiles) * 100
    print(f"    {label:<20} {count:>5}  ({pct:.1f}%)")
print()
print("  Attack type distribution:")
for atype, count in profiles["attack_type"].value_counts().items():
    pct = count / len(profiles) * 100
    print(f"    {atype:<25} {count:>5}  ({pct:.1f}%)")
print()
print("  Outputs written:")
print("    → attacker_profiles.csv")
print("    → attacker_alerts.log    (Wazuh-ingestible, matches cowrie_decoders.xml)")
print("    → cluster_summary.csv")
print("    → kmeans_model.pkl")
print()