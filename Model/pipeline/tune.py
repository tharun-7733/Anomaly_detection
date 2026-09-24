import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, precision_score, recall_score
from features.schema import FEATURE_NAMES
import datetime
import json

def tune_and_train(features_path, models_dir):
    print(f"Loading dataset from {features_path}...")
    df = pd.read_csv(features_path)
    
    # Sort by window_id to guarantee chronological sequence
    df = df.sort_values(by='window_id').reset_index(drop=True)
    
    unique_windows = sorted(df['window_id'].unique())
    total_windows = len(unique_windows)
    
    # Split: 60% Train (Benign only), 20% Validation, 20% Test
    train_idx = int(total_windows * 0.60)
    val_idx = int(total_windows * 0.80)
    
    train_windows = unique_windows[:train_idx]
    val_windows = unique_windows[train_idx:val_idx]
    test_windows = unique_windows[val_idx:]
    
    df_train_raw = df[df['window_id'].isin(train_windows)]
    df_val = df[df['window_id'].isin(val_windows)]
    df_test = df[df['window_id'].isin(test_windows)]
    
    # Train set is ONLY benign traffic
    df_train = df_train_raw[df_train_raw['label'] == 0].copy()
    
    print(f"Train set (Benign only): {len(df_train)} instances")
    print(f"Validation set (Mixed): {len(df_val)} instances")
    
    # Prepare features
    X_train = df_train[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan).fillna(0)
    X_val = df_val[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan).fillna(0)
    y_val = df_val['label'].values
    
    # To resolve imbalance in Isolation Forest, we tune hyperparameters on the validation set.
    # The contamination parameter acts as a threshold for anomaly scores.
    print("Fitting Scaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    
    # Define hyperparameter grid
    # Contamination defines the proportion of outliers in the data set. 
    # Since we train on purely benign, it might seem contamination should be 0, 
    # but in scikit-learn setting a small contamination helps define the decision boundary threshold.
    contaminations = [0.01, 0.05, 0.1, 0.15, 'auto']
    max_samples_options = [256, 512, 1024, 'auto']
    
    best_f1 = -1
    best_model = None
    best_params = {}
    
    print("\nStarting Hyperparameter Tuning...")
    for contam in contaminations:
        for max_samp in max_samples_options:
            print(f"Training IsolationForest(contamination={contam}, max_samples={max_samp})")
            clf = IsolationForest(
                n_estimators=200, 
                max_samples=max_samp,
                contamination=contam, 
                random_state=42, 
                n_jobs=-1
            )
            clf.fit(X_train_scaled)
            
            # Predict on validation set
            preds = clf.predict(X_val_scaled)
            # Map predictions: 1 inlier, -1 outlier => our labels: 0 benign, 1 attack
            y_val_pred = np.where(preds == -1, 1, 0)
            
            f1 = f1_score(y_val, y_val_pred, zero_division=0)
            prec = precision_score(y_val, y_val_pred, zero_division=0)
            rec = recall_score(y_val, y_val_pred, zero_division=0)
            
            print(f"  -> Val F1: {f1:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f}")
            
            if f1 > best_f1:
                best_f1 = f1
                best_model = clf
                best_params = {'contamination': contam, 'max_samples': max_samp}
                
    print("\n================ TUNE RESULTS ================")
    print(f"Best Parameters: {best_params}")
    print(f"Best Validation F1 Score: {best_f1:.4f}")
    
    # Save test dataset and best model
    os.makedirs(models_dir, exist_ok=True)
    df_test.to_csv('data/processed/test.csv', index=False)
    
    scaler_path = os.path.join(models_dir, 'scaler_tuned.pkl')
    model_path = os.path.join(models_dir, 'isolation_forest_tuned.pkl')
    
    joblib.dump(scaler, scaler_path)
    joblib.dump(best_model, model_path)
    
    print(f"Saved tuned model to {model_path}")
    print(f"Saved test dataset to data/processed/test.csv")

if __name__ == '__main__':
    tune_and_train('data/processed/features.csv', 'models')
