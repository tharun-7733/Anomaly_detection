import os
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from imblearn.over_sampling import BorderlineSMOTE
import xgboost as xgb
from features.session_schema import SESSION_FEATURE_NAMES


def train_session_model(features_path, models_dir):
    print(f"Loading session dataset from {features_path}...")
    df = pd.read_csv(features_path)

    # Chronological split by session_id (already ordered by PCAP time)
    df = df.sort_values(by='session_id').reset_index(drop=True)
    n = len(df)
    train_end = int(n * 0.60)
    val_end = int(n * 0.80)

    df_train = df.iloc[:train_end].copy()
    df_val = df.iloc[train_end:val_end].copy()
    df_test = df.iloc[val_end:].copy()

    print(f"Train: {len(df_train)} | Val: {len(df_val)} | Test: {len(df_test)}")

    X_train = df_train[SESSION_FEATURE_NAMES].replace([np.inf, -np.inf], np.nan).fillna(0).values
    X_val = df_val[SESSION_FEATURE_NAMES].replace([np.inf, -np.inf], np.nan).fillna(0).values
    X_test = df_test[SESSION_FEATURE_NAMES].replace([np.inf, -np.inf], np.nan).fillna(0).values

    y_train = df_train['label'].values
    y_val = df_val['label'].values
    y_test = df_test['label'].values
    label_names_test = df_test['label_name'].values

    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    n_benign = int(sum(y_train == 0))
    n_attack = int(sum(y_train == 1))
    scale_pos_weight = n_benign / max(n_attack, 1)
    print(f"\nTraining class balance — Benign: {n_benign} | Attack: {n_attack}")
    print(f"scale_pos_weight: {scale_pos_weight:.2f}")

    if n_attack < 6:
        print("ERROR: Too few attack sessions in training set.")
        return

    # BorderlineSMOTE — boundary-aware oversampling capped at 20x
    target_attack = min(n_attack * 20, n_benign // 2)
    sampling_strategy = target_attack / n_benign
    print(f"\nApplying BorderlineSMOTE (target attack samples: {target_attack})...")
    bsmote = BorderlineSMOTE(sampling_strategy=sampling_strategy, random_state=42, k_neighbors=5)
    X_resampled, y_resampled = bsmote.fit_resample(X_train_scaled, y_train)
    print(f"After SMOTE — Benign: {sum(y_resampled == 0)} | Attack: {sum(y_resampled == 1)}")

    print("\nTraining XGBoost...")
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=7,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=5,
        gamma=1,
        scale_pos_weight=scale_pos_weight,
        eval_metric='aucpr',
        early_stopping_rounds=20,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_resampled, y_resampled, eval_set=[(X_val_scaled, y_val)], verbose=50)

    # ---- Constrained threshold search on validation ----
    print("\nSearching for optimal threshold (max Recall with FPR <= budget)...")
    y_val_probs = model.predict_proba(X_val_scaled)[:, 1]
    n_benign_val = int(sum(y_val == 0))

    best_threshold = 0.5
    best_recall = 0.0
    chosen_fpr_budget = None

    for target_fpr in [0.05, 0.10, 0.15, 0.20]:
        max_fp = int(n_benign_val * target_fpr)
        for thresh in sorted(np.percentile(y_val_probs, np.arange(50, 100, 0.5)), reverse=True):
            preds = (y_val_probs >= thresh).astype(int)
            tn_, fp_, fn_, tp_ = confusion_matrix(y_val, preds, labels=[0, 1]).ravel()
            rec_ = tp_ / (tp_ + fn_ + 1e-9)
            if fp_ <= max_fp and rec_ > best_recall:
                best_recall = rec_
                best_threshold = thresh
                chosen_fpr_budget = target_fpr
        if best_recall > 0:
            break

    val_pred = (y_val_probs >= best_threshold).astype(int)
    val_tn, val_fp, val_fn, val_tp = confusion_matrix(y_val, val_pred, labels=[0, 1]).ravel()
    val_prec = precision_score(y_val, val_pred, zero_division=0)
    val_rec = recall_score(y_val, val_pred, zero_division=0)
    val_f1 = f1_score(y_val, val_pred, zero_division=0)
    val_fpr = val_fp / (val_tn + val_fp + 1e-9)
    print(f"Threshold: {best_threshold:.4f} (FPR budget: {chosen_fpr_budget})")
    print(f"  Val P: {val_prec:.4f} | R: {val_rec:.4f} | F1: {val_f1:.4f} | FPR: {val_fpr:.4f}")

    # ---- Test Evaluation ----
    print("\nEvaluating on Test Set...")
    y_test_probs = model.predict_proba(X_test_scaled)[:, 1]
    y_test_pred = (y_test_probs >= best_threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, y_test_pred, labels=[0, 1]).ravel()
    prec = precision_score(y_test, y_test_pred, zero_division=0)
    rec = recall_score(y_test, y_test_pred, zero_division=0)
    f1 = f1_score(y_test, y_test_pred, zero_division=0)
    fpr = fp / (tn + fp + 1e-9)

    print("\n==================== SESSION-BASED TEST METRICS ====================")
    print(f"Total Test Sessions:  {len(y_test)}")
    print(f"Threshold Used:       {best_threshold:.4f}")
    print(f"Confusion Matrix:")
    print(f"  TN: {tn} | FP: {fp}")
    print(f"  FN: {fn} | TP: {tp}")
    print(f"Precision:            {prec:.4f}")
    print(f"Recall/DR:            {rec:.4f}")
    print(f"F1 Score:             {f1:.4f}")
    print(f"False Positive Rate:  {fpr:.4f}")
    print("====================================================================\n")

    unique_labels = np.unique(label_names_test)
    print("================ PER-ATTACK METRIC REPORT ================")
    for attack in sorted(unique_labels):
        if attack == 'Normal':
            continue
        attack_mask = (label_names_test == attack)
        benign_mask = (y_test == 0)
        sub_mask = attack_mask | benign_mask
        sub_y_true = np.where(y_test[sub_mask] == 1, 1, 0)
        sub_y_pred = y_test_pred[sub_mask]
        sub_tn, sub_fp, sub_fn, sub_tp = confusion_matrix(sub_y_true, sub_y_pred, labels=[0, 1]).ravel()
        sub_rec = recall_score(sub_y_true, sub_y_pred, zero_division=0)
        sub_prec = precision_score(sub_y_true, sub_y_pred, zero_division=0)
        print(f"  {attack:20s}  Sessions: {sum(attack_mask):4d} | Detected: {sub_tp} ({sub_rec*100:.1f}%) | Prec: {sub_prec:.4f}")
    print("----------------------------------------------------------")

    # Feature importances
    fi = model.feature_importances_
    top_features = sorted(zip(SESSION_FEATURE_NAMES, fi), key=lambda x: -x[1])[:10]
    print("\nTop 10 Most Important Features:")
    for feat, imp in top_features:
        print(f"  {feat:30s}  {imp:.4f}")

    # Save
    os.makedirs(models_dir, exist_ok=True)
    joblib.dump(scaler, os.path.join(models_dir, 'session_scaler.pkl'))
    model.save_model(os.path.join(models_dir, 'xgboost_session.json'))
    with open(os.path.join(models_dir, 'session_threshold.txt'), 'w') as f:
        f.write(str(best_threshold))
    print(f"\nSaved model → models/xgboost_session.json")


if __name__ == '__main__':
    train_session_model('data/sessions/features.csv', 'models')
