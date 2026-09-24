"""
UNSW-NB15 Isolation Forest Training Pipeline
=============================================
- Loads labeled UNSW-NB15 CSVs (training-set + testing-set)
- Maps raw UNSW columns → project feature schema (14 core features)
- Trains a tuned IsolationForest (benign-only training, 37k samples)
- Evaluates on dedicated held-out testing-set (175k rows, 10 attack types)
- Removes old/failed model artifacts and saves new ones
- Updates feature_schema.json to reflect new training metadata
"""

import os
import glob
import json
import joblib
import datetime
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    confusion_matrix, precision_score, recall_score, f1_score
)

# ─────────────────────────────────────────────
# UNSW-NB15 column → project feature mapping
# ─────────────────────────────────────────────
# UNSW-NB15 raw column names (lowercase, as they appear in the CSV)
UNSW_COLUMN_MAP = {
    # project feature name   : UNSW-NB15 raw column
    'packets_per_second'     : 'rate',
    'bytes_per_second'       : 'sbytes',      # source bytes as proxy
    'mean_packet_size'       : 'smean',       # mean packet size (source)
    'std_packet_size'        : 'stcpb',       # TCP base seq no. used as size spread proxy
    'syn_ratio'              : 'synack',      # syn/ack ratio
    'ack_ratio'              : 'ackdat',      # ack/data ratio
    'rst_ratio'              : 'ct_state_ttl',# state TTL as rst proxy
    'fin_ratio'              : 'ct_dst_src_ltm',
    'unique_src_ips'         : 'ct_src_ltm',
    'unique_dst_ips'         : 'ct_dst_ltm',
    'unique_src_ports'       : 'ct_src_dport_ltm',
    'unique_dst_ports'       : 'ct_dst_sport_ltm',
    'connection_rate'        : 'ct_srv_src',
    'flow_duration'          : 'dur',
}

# UNSW-NB15 label column
UNSW_LABEL_COL      = 'label'       # 0 = normal, 1 = attack
UNSW_ATTACK_CAT_COL = 'attack_cat'  # attack category name

# Project paths
BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR   = os.path.join(BASE_DIR, 'dataset_anomaly', 'UNSW-NB15')
MODELS_DIR    = os.path.join(BASE_DIR, 'models')
DATA_DIR      = os.path.join(BASE_DIR, 'data', 'processed')

# Specific files to use (skip raw/duplicate CSVs)
TRAIN_FILE    = os.path.join(DATASET_DIR, 'UNSW_NB15_training-set.csv')
TEST_FILE     = os.path.join(DATASET_DIR, 'UNSW_NB15_testing-set.csv')

# ─────────────────────────────────────────────
# Old model artifacts to DELETE before saving new ones
# ─────────────────────────────────────────────
OLD_ARTIFACTS = [
    'isolation_forest.pkl',
    'isolation_forest_tuned.pkl',
    'scaler.pkl',
    'scaler_tuned.pkl',
    'feature_schema.json',
    'autoencoder.pth',
    'autoencoder_scaler.pkl',
]

FEATURE_NAMES = list(UNSW_COLUMN_MAP.keys())   # 14 core features


# ══════════════════════════════════════════════════════════
#  STEP 1: Load labeled UNSW-NB15 training & test CSVs
# ══════════════════════════════════════════════════════════
def load_unsw(train_file, test_file):
    for fpath in [train_file, test_file]:
        if not os.path.exists(fpath):
            raise FileNotFoundError(
                f"\n❌ Required file not found:\n   {fpath}\n"
                f"   → Place it inside dataset_anomaly/UNSW-NB15/ and retry."
            )

    print("📂 Loading labeled UNSW-NB15 files...")
    df_train = pd.read_csv(train_file, low_memory=False)
    df_test  = pd.read_csv(test_file,  low_memory=False)
    df_train.columns = df_train.columns.str.strip().str.lower()
    df_test.columns  = df_test.columns.str.strip().str.lower()

    print(f"   ✅ Training file : {os.path.basename(train_file)}  → {len(df_train):,} rows")
    print(f"   ✅ Testing file  : {os.path.basename(test_file)}   → {len(df_test):,} rows")
    return df_train, df_test


# ══════════════════════════════════════════════════════════
#  STEP 2: Map UNSW columns → project feature schema
# ══════════════════════════════════════════════════════════
def map_features(df, tag=''):
    print(f"\n🔄 Mapping UNSW-NB15 columns → project features {tag}")

    missing = [feat for feat, col in UNSW_COLUMN_MAP.items() if col not in df.columns]
    if missing:
        print(f"   ⚠️  {len(missing)} feature(s) missing — filling with 0.0: {missing}")

    rows = {}
    for feat, raw_col in UNSW_COLUMN_MAP.items():
        rows[feat] = pd.to_numeric(df[raw_col], errors='coerce') if raw_col in df.columns else 0.0
    X = pd.DataFrame(rows)

    # Label column (numeric 0/1)
    if UNSW_LABEL_COL not in df.columns:
        raise ValueError(f"Label column '{UNSW_LABEL_COL}' not found.")
    y = pd.to_numeric(df[UNSW_LABEL_COL], errors='coerce').fillna(0).astype(int)

    # Attack category names — 'Normal' string used for benign rows
    cat_col = UNSW_ATTACK_CAT_COL if UNSW_ATTACK_CAT_COL in df.columns else None
    if cat_col:
        label_names = df[cat_col].fillna('Normal').astype(str).str.strip()
        label_names = label_names.replace({'': 'Normal', 'nan': 'Normal', '0': 'Normal'})
    else:
        label_names = pd.Series(np.where(y == 0, 'Normal', 'Attack'), index=y.index)

    print(f"   ✅ Shape: {X.shape}  |  Normal: {(y==0).sum():,}  |  Attack: {(y==1).sum():,}  "
          f"({(y==1).mean()*100:.1f}%)")
    return X, y, label_names


# ══════════════════════════════════════════════════════════
#  STEP 3: Clean each split separately (train / val from training-set,
#          test from dedicated testing-set)
# ══════════════════════════════════════════════════════════
def clean_df(X):
    X = X.replace([np.inf, -np.inf], np.nan)
    return X.fillna(X.median())

def prepare_splits(X_tr_raw, y_tr_raw, lnames_tr,
                   X_te_raw, y_te_raw, lnames_te,
                   val_ratio=0.20):
    """Split training-set into train (benign-only) + val (mixed).
       Keep testing-set as the final held-out test split."""
    print("\n🧹 Cleaning & splitting...")
    X_tr_raw = clean_df(X_tr_raw)
    X_te_raw = clean_df(X_te_raw)

    n = len(X_tr_raw)
    idx = np.arange(n)
    np.random.seed(42)
    np.random.shuffle(idx)

    val_cut   = int(n * (1 - val_ratio))
    train_idx = idx[:val_cut]
    val_idx   = idx[val_cut:]

    # Train: benign only
    benign_mask      = y_tr_raw.values[train_idx] == 0
    train_idx_benign = train_idx[benign_mask]

    X_train       = X_tr_raw.iloc[train_idx_benign].values
    X_val         = X_tr_raw.iloc[val_idx].values
    y_val         = y_tr_raw.values[val_idx]
    lnames_val    = lnames_tr.values[val_idx]

    X_test        = X_te_raw.values
    y_test        = y_te_raw.values
    lnames_test   = lnames_te.values

    print(f"   Train (benign only) : {len(X_train):,}")
    print(f"   Validation (mixed)  : {len(X_val):,}  "
          f"[benign={sum(y_val==0):,}  attacks={sum(y_val==1):,}]")
    print(f"   Test  (mixed)       : {len(X_test):,}  "
          f"[benign={sum(y_test==0):,}  attacks={sum(y_test==1):,}]")

    return X_train, X_val, X_test, y_val, y_test, lnames_test


# ══════════════════════════════════════════════════════════
#  STEP 4: Scale
# ══════════════════════════════════════════════════════════
def fit_scaler(X_train, X_val, X_test):
    print("\n📐 Fitting StandardScaler on training set...")
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s   = scaler.transform(X_val)
    X_test_s  = scaler.transform(X_test)
    return scaler, X_train_s, X_val_s, X_test_s


# ══════════════════════════════════════════════════════════
#  STEP 5: Tune & Train Isolation Forest
# ══════════════════════════════════════════════════════════
def tune_and_train_if(X_train_s, X_val_s, y_val):
    # contamination = actual attack ratio observed (UNSW ~13%)
    contaminations  = [0.05, 0.10, 0.13, 0.15, 0.20]
    max_samples_opts = [256, 512, 1024, 'auto']

    best_f1     = -1.0
    best_model  = None
    best_params = {}

    print("\n🔍 Hyperparameter tuning (contamination × max_samples)...")
    for contam in contaminations:
        for max_samp in max_samples_opts:
            clf = IsolationForest(
                n_estimators=300,
                contamination=contam,
                max_samples=max_samp,
                max_features=0.8,
                random_state=42,
                n_jobs=-1,
            )
            clf.fit(X_train_s)
            preds  = clf.predict(X_val_s)
            y_pred = np.where(preds == -1, 1, 0)

            f1   = f1_score(y_val, y_pred, zero_division=0)
            prec = precision_score(y_val, y_pred, zero_division=0)
            rec  = recall_score(y_val, y_pred, zero_division=0)
            print(f"   contamination={str(contam):<5} max_samples={str(max_samp):<5} "
                  f"→ F1={f1:.4f}  Prec={prec:.4f}  Rec={rec:.4f}")

            if f1 > best_f1:
                best_f1     = f1
                best_model  = clf
                best_params = {'contamination': contam, 'max_samples': max_samp}

    print(f"\n✅ Best params : {best_params}")
    print(f"   Best Val F1  : {best_f1:.4f}")
    return best_model, best_params, best_f1


# ══════════════════════════════════════════════════════════
#  STEP 6: Evaluate on Test Set
# ══════════════════════════════════════════════════════════
def evaluate(model, X_test_s, y_test, lnames_test):
    preds  = model.predict(X_test_s)
    y_pred = np.where(preds == -1, 1, 0)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    fpr  = float(fp) / (tn + fp) if (tn + fp) > 0 else 0.0

    print("\n" + "="*55)
    print("  ISOLATION FOREST — TEST SET RESULTS (UNSW-NB15)")
    print("="*55)
    print(f"  Total Samples : {len(y_test):,}")
    print(f"  TN={tn:,}  FP={fp:,}")
    print(f"  FN={fn:,}  TP={tp:,}")
    print(f"  Precision          : {prec:.4f}")
    print(f"  Recall / Det. Rate : {rec:.4f}  ({rec*100:.2f}%)")
    print(f"  F1 Score           : {f1:.4f}")
    print(f"  False Positive Rate: {fpr:.4f}  ({fpr*100:.2f}%)")
    print("="*55)

    results = [{
        'category': 'Overall', 'total_samples': len(y_test),
        'true_positives': int(tp), 'false_positives': int(fp),
        'true_negatives': int(tn), 'false_negatives': int(fn),
        'precision': prec, 'recall': rec, 'f1_score': f1,
        'false_positive_rate': fpr,
    }]

    unique_attacks = [a for a in np.unique(lnames_test) if a not in ('Normal', '0', 'nan', '')]
    if unique_attacks:
        print("\n  PER-ATTACK BREAKDOWN")
        print("-"*55)
        for attack in sorted(unique_attacks):
            am = (lnames_test == attack)
            bm = (y_test == 0)
            sm = am | bm
            sy_t = np.where(y_test[sm] == 1, 1, 0)
            sy_p = y_pred[sm]
            try:
                st, sf, sfn, stp = confusion_matrix(sy_t, sy_p, labels=[0, 1]).ravel()
            except ValueError:
                continue
            sr  = recall_score(sy_t, sy_p, zero_division=0)
            sp  = precision_score(sy_t, sy_p, zero_division=0)
            sf1 = f1_score(sy_t, sy_p, zero_division=0)
            sfpr = float(sf) / (st + sf) if (st + sf) > 0 else 0.0
            print(f"  [{attack}]")
            print(f"    Samples={sum(am):,}  Detected={stp}  ({sr*100:.1f}%)  "
                  f"Missed={sfn}  Prec={sp:.4f}  F1={sf1:.4f}")
            results.append({
                'category': attack, 'total_samples': int(sum(am)),
                'true_positives': int(stp), 'false_positives': int(sf),
                'true_negatives': int(st), 'false_negatives': int(sfn),
                'precision': sp, 'recall': sr, 'f1_score': sf1,
                'false_positive_rate': sfpr,
            })
        print("-"*55)

    return pd.DataFrame(results), prec, rec, f1, fpr


# ══════════════════════════════════════════════════════════
#  STEP 7: Remove old artifacts & Save new ones
# ══════════════════════════════════════════════════════════
def cleanup_old_models(models_dir):
    print("\n🗑  Removing old/failed model artifacts...")
    removed = []
    for fname in OLD_ARTIFACTS:
        fpath = os.path.join(models_dir, fname)
        if os.path.exists(fpath):
            os.remove(fpath)
            removed.append(fname)
            print(f"   ❌ Deleted: {fname}")
    if not removed:
        print("   (nothing to remove)")


def save_artifacts(models_dir, data_dir, scaler, model, best_params,
                   val_f1, test_f1, test_rec, test_fpr, df_results, n_train):
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)

    scaler_path  = os.path.join(models_dir, 'scaler.pkl')
    model_path   = os.path.join(models_dir, 'isolation_forest.pkl')
    schema_path  = os.path.join(models_dir, 'feature_schema.json')
    results_path = os.path.join(data_dir, 'evaluation_results_unsw.csv')

    joblib.dump(scaler, scaler_path)
    print(f"\n💾 Saved scaler        → {scaler_path}")

    joblib.dump(model, model_path)
    print(f"💾 Saved IF model      → {model_path}")

    schema = {
        'feature_names'      : FEATURE_NAMES,
        'n_features'         : len(FEATURE_NAMES),
        'model'              : 'IsolationForest',
        'dataset'            : 'UNSW-NB15',
        'n_estimators'       : 300,
        'max_features'       : 0.8,
        'contamination'      : best_params['contamination'],
        'max_samples'        : best_params['max_samples'],
        'training_rows'      : n_train,
        'val_f1'             : round(val_f1, 6),
        'test_f1'            : round(test_f1, 6),
        'test_recall'        : round(test_rec, 6),
        'test_fpr'           : round(test_fpr, 6),
        'created_at'         : datetime.datetime.utcnow().isoformat() + '+00:00',
    }
    with open(schema_path, 'w') as f:
        json.dump(schema, f, indent=4)
    print(f"💾 Saved feature schema → {schema_path}")

    df_results.to_csv(results_path, index=False)
    print(f"💾 Saved eval results  → {results_path}")


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════
def main():
    print("=" * 55)
    print("  UNSW-NB15 Isolation Forest Training Pipeline")
    print("=" * 55)

    # 1. Load
    df_train_raw, df_test_raw = load_unsw(TRAIN_FILE, TEST_FILE)

    # 2. Map features
    X_tr, y_tr, lnames_tr = map_features(df_train_raw, tag='[train]')
    X_te, y_te, lnames_te = map_features(df_test_raw,  tag='[test]')

    # 3. Split
    X_train, X_val, X_test, y_val, y_test, lnames_test = prepare_splits(
        X_tr, y_tr, lnames_tr, X_te, y_te, lnames_te
    )

    # 4. Scale
    scaler, X_train_s, X_val_s, X_test_s = fit_scaler(X_train, X_val, X_test)

    # 5. Tune & Train
    model, best_params, best_val_f1 = tune_and_train_if(X_train_s, X_val_s, y_val)

    # 6. Evaluate
    df_results, prec, rec, f1, fpr = evaluate(model, X_test_s, y_test, lnames_test)

    # 7. Cleanup old → Save new
    cleanup_old_models(MODELS_DIR)
    save_artifacts(
        MODELS_DIR, DATA_DIR,
        scaler, model, best_params,
        best_val_f1, f1, rec, fpr,
        df_results, len(X_train)
    )

    print("\n✅ Pipeline complete!")
    print(f"   Detection Rate : {rec*100:.2f}%")
    print(f"   F1 Score       : {f1:.4f}")
    print(f"   FPR            : {fpr*100:.2f}%")


if __name__ == '__main__':
    main()
