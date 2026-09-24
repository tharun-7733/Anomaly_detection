import os
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from features.schema import FEATURE_NAMES

def evaluate_pipeline(test_csv, scaler_path, model_path, results_out_path):
    if not os.path.exists(test_csv):
        raise FileNotFoundError(f"Test dataset not found: {test_csv}")
    if not os.path.exists(scaler_path) or not os.path.exists(model_path):
        raise FileNotFoundError("Required model or scaler artifact is missing.")

    print(f"Loading data from {test_csv}...")
    # Load Test Data
    df_test = pd.read_csv(test_csv)
    X = df_test[FEATURE_NAMES].copy()
    y_true = df_test['label'].values
    label_names = df_test['label_name'].values

    print("Preprocessing data...")
    # Preprocessing
    X = X.replace([np.inf, -np.inf], np.nan)
    if X.isnull().any().any():
        X = X.fillna(X.median())

    print("Loading model and scaler...")
    # Load Artifacts
    scaler = joblib.load(scaler_path)
    model = joblib.load(model_path)

    print("Scaling features...")
    # Scale Features
    X_scaled = scaler.transform(X)

    print("Running predictions...")
    # Predict anomalies
    # Isolation Forest predicts -1 for anomalies, 1 for inliers (normal)
    # We convert to our ground truth label schema: 0 = Benign, 1 = Anomaly
    raw_predictions = model.predict(X_scaled)
    y_pred = np.where(raw_predictions == -1, 1, 0)
    decision_scores = model.decision_function(X_scaled)

    # Compute Metrics
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    # Security metrics
    fpr = float(fp) / (tn + fp) if (tn + fp) > 0 else 0.0
    dr = float(tp) / (tp + fn) if (tp + fn) > 0 else 0.0  # Equivalent to recall/tpr

    print("\n==================== OVERALL METRICS ====================")
    print(f"Total Test Instances: {len(df_test)}")
    print(f"Confusion Matrix:")
    print(f"  TN: {tn} | FP: {fp}")
    print(f"  FN: {fn} | TP: {tp}")
    print(f"Precision:          {precision:.4f}")
    print(f"Recall/DR:          {recall:.4f}")
    print(f"F1 Score:           {f1:.4f}")
    print(f"False Positive Rate: {fpr:.4f}")
    print(f"Total False Positives: {fp}")
    print(f"Total False Negatives: {fn}")
    print("=========================================================\n")

    # Store results in a list to convert to DataFrame
    results_records = []
    results_records.append({
        "category": "Overall",
        "total_samples": len(df_test),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall_or_detection_rate": dr,
        "f1_score": f1,
        "false_positive_rate": fpr
    })

    # Report results for each attack category present in test set
    unique_labels = df_test['label_name'].unique()
    has_attacks = any(lbl != 'Normal' for lbl in unique_labels)

    if has_attacks:
        print("================ PER-ATTACK METRIC REPORT ================")
        for attack in unique_labels:
            if attack == 'Normal':
                continue
            # Mask for specific attack + benign instances to compute relative metrics
            attack_mask = (label_names == attack)
            benign_mask = (y_true == 0)
            sub_mask = attack_mask | benign_mask

            sub_y_true = np.where(y_true[sub_mask] == 1, 1, 0)
            sub_y_pred = y_pred[sub_mask]
            
            sub_tn, sub_fp, sub_fn, sub_tp = confusion_matrix(sub_y_true, sub_y_pred, labels=[0, 1]).ravel()
            sub_prec = precision_score(sub_y_true, sub_y_pred, zero_division=0)
            sub_rec = recall_score(sub_y_true, sub_y_pred, zero_division=0)
            sub_f1 = f1_score(sub_y_true, sub_y_pred, zero_division=0)
            sub_fpr = float(sub_fp) / (sub_tn + sub_fp) if (sub_tn + sub_fp) > 0 else 0.0

            print(f"Attack Category: {attack}")
            print(f"  Samples: {sum(attack_mask)} | Detected: {sub_tp} ({sub_rec*100:.2f}%) | Missed: {sub_fn}")
            print(f"  Category F1: {sub_f1:.4f} | Category Precision: {sub_prec:.4f}")
            print("---------------------------------------------------------")

            results_records.append({
                "category": attack,
                "total_samples": int(sum(attack_mask)),
                "true_positives": int(sub_tp),
                "false_positives": int(sub_fp),
                "true_negatives": int(sub_tn),
                "false_negatives": int(sub_fn),
                "precision": sub_prec,
                "recall_or_detection_rate": sub_rec,
                "f1_score": sub_f1,
                "false_positive_rate": sub_fpr
            })
        print("=========================================================\n")

    # Save to CSV
    os.makedirs(os.path.dirname(results_out_path), exist_ok=True)
    df_results = pd.DataFrame(results_records)
    df_results.to_csv(results_out_path, index=False)
    print(f"Evaluation results saved to: {results_out_path}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--test-csv', default='data/processed/features.csv')
    parser.add_argument('--scaler', default='models/scaler.pkl')
    parser.add_argument('--model', default='models/isolation_forest.pkl')
    parser.add_argument('--output', default='data/processed/evaluation_results.csv')
    args = parser.parse_args()

    evaluate_pipeline(
        test_csv=args.test_csv,
        scaler_path=args.scaler,
        model_path=args.model,
        results_out_path=args.output
    )
