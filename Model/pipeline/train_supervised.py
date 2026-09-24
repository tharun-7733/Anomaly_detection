import os
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, precision_recall_curve
from imblearn.over_sampling import BorderlineSMOTE
import xgboost as xgb
from features.schema import FEATURE_NAMES

def train_supervised_smote(features_path, models_dir):
    print(f"Loading dataset from {features_path}...")
    df = pd.read_csv(features_path)

    # Sort chronologically
    df = df.sort_values(by='window_id').reset_index(drop=True)

    unique_windows = sorted(df['window_id'].unique())
    total_windows = len(unique_windows)

    # Chronological split: 60/20/20
    train_idx = int(total_windows * 0.60)
    val_idx = int(total_windows * 0.80)

    train_windows = unique_windows[:train_idx]
    val_windows = unique_windows[train_idx:val_idx]
    test_windows = unique_windows[val_idx:]

    df_train = df[df['window_id'].isin(train_windows)].copy()
    df_val = df[df['window_id'].isin(val_windows)].copy()
    df_test = df[df['window_id'].isin(test_windows)].copy()

    print(f"Train set (Mixed): {len(df_train)} instances")
    print(f"Validation set (Mixed): {len(df_val)} instances")
    print(f"Test set (Mixed): {len(df_test)} instances")

    # Feature extraction & NaN handling
    X_train = df_train[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan).fillna(0).values
    X_val = df_val[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan).fillna(0).values
    X_test = df_test[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan).fillna(0).values

    y_train = df_train['label'].values
    y_val = df_val['label'].values
    y_test = df_test['label'].values
    label_names_test = df_test['label_name'].values

    # Scaling
    print("Fitting Scaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    # Class imbalance stats
    n_benign = int(sum(y_train == 0))
    n_attack = int(sum(y_train == 1))
    scale_pos_weight = n_benign / max(n_attack, 1)

    print(f"\nClass distribution in training set:")
    print(f"  - Benign (0): {n_benign}")
    print(f"  - Attack (1): {n_attack}")
    print(f"  - scale_pos_weight set to: {scale_pos_weight:.2f}")

    if n_attack < 6:
        print("Error: Not enough attacks in the training set to perform BorderlineSMOTE.")
        return

    # BorderlineSMOTE: generates synthetic samples only at class boundaries
    # This prevents confusing the model with generic SMOTE samples that can overlap with benign
    print("\nApplying BorderlineSMOTE (boundary-aware oversampling)...")
    # Only oversample to 20x the attack count, not full balance — avoids overwhelming the model
    target_attack_count = min(n_attack * 20, n_benign // 2)
    sampling_strategy = target_attack_count / n_benign
    bsmote = BorderlineSMOTE(
        sampling_strategy=sampling_strategy,
        random_state=42,
        k_neighbors=5
    )
    X_train_resampled, y_train_resampled = bsmote.fit_resample(X_train_scaled, y_train)

    print(f"After BorderlineSMOTE:")
    print(f"  - Benign (0): {sum(y_train_resampled == 0)}")
    print(f"  - Attack (1): {sum(y_train_resampled == 1)}")

    print("\nTraining XGBoost Classifier with weighted loss...")
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=7,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=5,
        gamma=1,
        # Weight real attack samples higher during training so the model
        # doesn't become overconfident on synthetic SMOTE samples
        scale_pos_weight=scale_pos_weight,
        eval_metric='aucpr',     # Area under Precision-Recall curve — better for imbalanced data
        early_stopping_rounds=20,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(
        X_train_resampled,
        y_train_resampled,
        eval_set=[(X_val_scaled, y_val)],
        verbose=50
    )

    # ---- Constrained Threshold Search ----
    # Goal: maximize Recall subject to FPR <= target_fpr budget.
    # This prevents the optimizer from choosing a threshold that flags 90% of
    # benign traffic just to catch more attacks.
    print("\nSearching for best threshold (maximize Recall where FPR <= target)...")
    y_val_probs = model.predict_proba(X_val_scaled)[:, 1]

    n_benign_val = int(sum(y_val == 0))
    TARGET_FPRS = [0.05, 0.10, 0.15, 0.20]  # Try progressively relaxed budgets

    best_threshold = 0.5
    best_recall = 0.0
    chosen_fpr_budget = None

    for target_fpr in TARGET_FPRS:
        max_fp_allowed = int(n_benign_val * target_fpr)
        # Sweep thresholds from high to low to find the lowest thresh where FP <= budget
        candidate_thresholds = np.percentile(y_val_probs, np.arange(50, 100, 0.5))
        for thresh in sorted(candidate_thresholds, reverse=True):
            preds = (y_val_probs >= thresh).astype(int)
            tn_, fp_, fn_, tp_ = confusion_matrix(y_val, preds, labels=[0, 1]).ravel()
            fpr_ = float(fp_) / (tn_ + fp_ + 1e-9)
            rec_ = float(tp_) / (tp_ + fn_ + 1e-9)
            if fp_ <= max_fp_allowed and rec_ > best_recall:
                best_recall = rec_
                best_threshold = thresh
                chosen_fpr_budget = target_fpr
        if best_recall > 0:
            break  # Found a working budget, stop

    val_pred_opt = (y_val_probs >= best_threshold).astype(int)
    val_prec = precision_score(y_val, val_pred_opt, zero_division=0)
    val_rec = recall_score(y_val, val_pred_opt, zero_division=0)
    val_tn, val_fp, val_fn, val_tp = confusion_matrix(y_val, val_pred_opt, labels=[0, 1]).ravel()
    val_fpr = float(val_fp) / (val_tn + val_fp + 1e-9)
    val_f1 = f1_score(y_val, val_pred_opt, zero_division=0)
    print(f"Optimal Threshold: {best_threshold:.4f} (FPR budget: {chosen_fpr_budget})")
    print(f"  Val Precision: {val_prec:.4f} | Val Recall: {val_rec:.4f} | Val F1: {val_f1:.4f}")
    print(f"  Val FPR: {val_fpr:.4f} | Val TP: {val_tp} | Val FP: {val_fp}")

    # ---- Final Test Evaluation ----
    print("\nEvaluating on Test Set...")
    y_test_probs = model.predict_proba(X_test_scaled)[:, 1]
    y_test_pred = (y_test_probs >= best_threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, y_test_pred, labels=[0, 1]).ravel()
    prec = precision_score(y_test, y_test_pred, zero_division=0)
    rec = recall_score(y_test, y_test_pred, zero_division=0)
    f1 = f1_score(y_test, y_test_pred, zero_division=0)
    fpr = float(fp) / (tn + fp) if (tn + fp) > 0 else 0.0

    print("\n==================== TEST SET METRICS ====================")
    print(f"Total Test Instances: {len(y_test)}")
    print(f"Optimal Threshold Used: {best_threshold:.4f}")
    print(f"Confusion Matrix:")
    print(f"  TN: {tn} | FP: {fp}")
    print(f"  FN: {fn} | TP: {tp}")
    print(f"Precision:          {prec:.4f}")
    print(f"Recall/DR:          {rec:.4f}")
    print(f"F1 Score:           {f1:.4f}")
    print(f"False Positive Rate: {fpr:.4f}")
    print("=========================================================\n")

    # Per Attack Breakdown
    unique_labels = np.unique(label_names_test)
    has_attacks = any(lbl != 'Normal' for lbl in unique_labels)
    if has_attacks:
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
            print(f"Attack Category: {attack}")
            print(f"  Samples: {sum(attack_mask)} | Detected: {sub_tp} ({sub_rec*100:.2f}%) | Missed: {sub_fn} | Precision: {sub_prec:.4f}")
            print("---------------------------------------------------------")

    # Save artifacts
    os.makedirs(models_dir, exist_ok=True)
    scaler_path = os.path.join(models_dir, 'supervised_scaler.pkl')
    model_path = os.path.join(models_dir, 'xgboost_supervised.json')
    threshold_path = os.path.join(models_dir, 'optimal_threshold.txt')

    joblib.dump(scaler, scaler_path)
    model.save_model(model_path)
    with open(threshold_path, 'w') as f:
        f.write(str(best_threshold))

    print(f"\nSaved XGBoost model to {model_path}")
    print(f"Saved Scaler to {scaler_path}")
    print(f"Saved threshold ({best_threshold:.4f}) to {threshold_path}")


if __name__ == '__main__':
    train_supervised_smote('data/processed/features.csv', 'models')
