"""
data_preparation.py
─────────────────────────────────────────────────────────────────────────
Reproducible data cleaning & feature engineering script for the
Cyber Security Threat Analytics Dashboard.

Input : data/Train_data.csv, data/Test_data.csv  (NSL-KDD intrusion dataset)
Output: data/cleaned_data.csv, data/quality_log.json

Run:  python notebooks/data_preparation.py
─────────────────────────────────────────────────────────────────────────
"""
import pandas as pd
import numpy as np
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

TRAIN_PATH = os.path.join(DATA_DIR, "Train_data.csv")
TEST_PATH  = os.path.join(DATA_DIR, "Test_data.csv")
OUT_PATH   = os.path.join(DATA_DIR, "cleaned_data.csv")
LOG_PATH   = os.path.join(DATA_DIR, "quality_log.json")


def main():
    # ── STEP 1: LOAD ─────────────────────────────────────────────────────
    train = pd.read_csv(TRAIN_PATH)
    test = pd.read_csv(TEST_PATH)

    # Test_data.csv has no 'class' column in the source file.
    # We label these rows 'unlabeled' — an honest flag, not a guess.
    test = test.copy()
    test["class"] = "unlabeled"

    df = pd.concat([train, test], ignore_index=True)
    print(f"Combined shape: {df.shape}")

    # ── STEP 2: DATA CLEANING ───────────────────────────────────────────
    before = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    dup_removed = before - len(df)
    print(f"Duplicates removed: {dup_removed}")

    missing_total = int(df.isnull().sum().sum())
    print(f"Missing values found: {missing_total}")

    # Standardize categorical text
    for col in ["protocol_type", "service", "flag", "class"]:
        df[col] = df[col].astype(str).str.strip().str.lower()

    # Enforce correct dtypes per the known NSL-KDD schema
    int_cols = ["duration", "src_bytes", "dst_bytes", "land", "wrong_fragment",
                "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
                "root_shell", "su_attempted", "num_root", "num_file_creations",
                "num_shells", "num_access_files", "num_outbound_cmds",
                "is_host_login", "is_guest_login", "count", "srv_count",
                "dst_host_count", "dst_host_srv_count"]
    for c in int_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)

    float_cols = ["serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
                  "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
                  "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                  "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
                  "dst_host_serror_rate", "dst_host_srv_serror_rate",
                  "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]
    for c in float_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    # Outlier capping using IQR x 3 (preserves records, removes extreme noise)
    num_cols = df.select_dtypes(include=[np.number]).columns
    outlier_log = {}
    for col in num_cols:
        q1, q3 = df[col].quantile(0.25), df[col].quantile(0.75)
        iqr = q3 - q1
        lo, hi = q1 - 3 * iqr, q3 + 3 * iqr
        n_out = int(((df[col] < lo) | (df[col] > hi)).sum())
        outlier_log[col] = n_out
        df[col] = df[col].clip(lower=lo, upper=hi)

    # ── STEP 3: FEATURE ENGINEERING (only from real columns) ────────────
    # TotalTraffic = src_bytes + dst_bytes
    df["total_traffic"] = df["src_bytes"] + df["dst_bytes"]

    # TrafficCategory — data-driven terciles of total_traffic
    q33, q66 = df["total_traffic"].quantile([0.33, 0.66])
    df["traffic_category"] = df["total_traffic"].apply(
        lambda v: "Low Traffic" if v <= q33 else ("Medium Traffic" if v <= q66 else "High Traffic")
    )

    # ThreatLevel — composite of native intrusion-indicator columns
    def threat_level(row):
        score = 0
        if row["class"] == "anomaly": score += 3
        if row["root_shell"] == 1: score += 2
        if row["num_failed_logins"] > 0: score += 1
        if row["wrong_fragment"] > 0: score += 1
        if row["su_attempted"] > 0: score += 1
        if row["serror_rate"] > 0.5: score += 1
        if score >= 4: return "High"
        elif score >= 2: return "Medium"
        return "Low"
    df["threat_level"] = df.apply(threat_level, axis=1)

    # ConnectionCategory — based on duration
    df["connection_category"] = df["duration"].apply(
        lambda d: "Instant" if d == 0 else ("Short" if d < 60 else ("Medium" if d < 600 else "Long"))
    )

    # RiskScore (0-100) — composite of native columns
    def risk_score(row):
        s = 0
        if row["class"] == "anomaly": s += 40
        if row["root_shell"]: s += 20
        if row["su_attempted"]: s += 10
        if row["num_failed_logins"] > 0: s += 10
        if row["wrong_fragment"] > 0: s += 5
        if row["urgent"] > 0: s += 10
        if row["serror_rate"] > 0.5: s += 5
        return min(s, 100)
    df["risk_score"] = df.apply(risk_score, axis=1)

    # AttackSeverity — derived from RiskScore
    df["attack_severity"] = df["risk_score"].apply(
        lambda r: "Critical" if r >= 70 else ("High" if r >= 40 else ("Medium" if r >= 20 else "Low"))
    )

    # record_index — sequence proxy only (NOT a real timestamp; dataset has none)
    df["record_index"] = df.index

    # ── STEP 4: SAVE ─────────────────────────────────────────────────────
    df.to_csv(OUT_PATH, index=False)
    print(f"Saved cleaned dataset: {OUT_PATH}  shape={df.shape}")

    quality_log = {
        "duplicates_removed": int(dup_removed),
        "missing_values_found": missing_total,
        "total_records_before": int(before),
        "total_records_after": int(len(df)),
        "outlier_counts_by_column": outlier_log,
    }
    with open(LOG_PATH, "w") as f:
        json.dump(quality_log, f, indent=2)
    print(f"Saved quality log: {LOG_PATH}")


if __name__ == "__main__":
    main()
