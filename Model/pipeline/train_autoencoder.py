import os
import joblib
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from features.schema import FEATURE_NAMES

# Define the Autoencoder model
class AnomalyAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(AnomalyAutoencoder, self).__init__()
        # Compression
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 10),
            nn.ReLU(True),
            nn.Linear(10, 5),
            nn.ReLU(True)
        )
        # Reconstruction
        self.decoder = nn.Sequential(
            nn.Linear(5, 10),
            nn.ReLU(True),
            nn.Linear(10, input_dim)
        )
        
    def forward(self, x):
        x = self.encoder(x)
        x = self.decoder(x)
        return x

def train_and_evaluate(features_path, models_dir):
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
    
    df_train_raw = df[df['window_id'].isin(train_windows)]
    df_val = df[df['window_id'].isin(val_windows)]
    df_test = df[df['window_id'].isin(test_windows)]
    
    # Unsupervised: Train only on benign data
    df_train = df_train_raw[df_train_raw['label'] == 0].copy()
    
    print(f"Train set (Benign only): {len(df_train)} instances")
    print(f"Validation set (Mixed): {len(df_val)} instances")
    print(f"Test set (Mixed): {len(df_test)} instances")
    
    # Feature extraction & NaN handling
    X_train = df_train[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan).fillna(0).values
    X_val = df_val[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan).fillna(0).values
    X_test = df_test[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan).fillna(0).values
    
    y_val = df_val['label'].values
    y_test = df_test['label'].values
    label_names_test = df_test['label_name'].values
    
    # Scaling
    print("Fitting Scaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)
    
    # Convert to PyTorch tensors
    train_tensor = torch.tensor(X_train_scaled, dtype=torch.float32)
    val_tensor = torch.tensor(X_val_scaled, dtype=torch.float32)
    test_tensor = torch.tensor(X_test_scaled, dtype=torch.float32)
    
    # Create DataLoaders
    batch_size = 256
    train_loader = DataLoader(TensorDataset(train_tensor, train_tensor), batch_size=batch_size, shuffle=True)
    
    # Model Setup
    input_dim = len(FEATURE_NAMES)
    model = AnomalyAutoencoder(input_dim)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=1e-3)
    
    # Training Loop
    epochs = 15
    print("\nTraining Autoencoder...")
    model.train()
    for epoch in range(epochs):
        train_loss = 0.0
        for data, _ in train_loader:
            optimizer.zero_grad()
            outputs = model(data)
            loss = criterion(outputs, data)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * data.size(0)
        train_loss /= len(train_loader.dataset)
        print(f"Epoch {epoch+1}/{epochs} - Training Loss: {train_loss:.4f}")
        
    # Validation phase to find optimal threshold
    print("\nFinding optimal anomaly threshold on Validation Set...")
    model.eval()
    with torch.no_grad():
        val_preds = model(val_tensor)
        # Calculate Mean Squared Error (MSE) per instance for validation set
        val_mse = torch.mean((val_tensor - val_preds)**2, dim=1).numpy()
    
    # Test different thresholds (percentiles of benign reconstruction errors or grid search)
    thresholds = np.percentile(val_mse, np.arange(80, 100, 0.5))
    best_threshold = 0
    best_f1 = -1
    
    for thresh in thresholds:
        # If error > threshold, we flag it as an anomaly (1), else benign (0)
        y_val_pred = (val_mse > thresh).astype(int)
        f1 = f1_score(y_val, y_val_pred, zero_division=0)
        
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = thresh
            
    print(f"Optimal Threshold: {best_threshold:.4f} (Val F1: {best_f1:.4f})")
    
    # Test Phase
    print("\nEvaluating on Test Set...")
    with torch.no_grad():
        test_preds = model(test_tensor)
        test_mse = torch.mean((test_tensor - test_preds)**2, dim=1).numpy()
        
    y_test_pred = (test_mse > best_threshold).astype(int)
    
    tn, fp, fn, tp = confusion_matrix(y_test, y_test_pred, labels=[0, 1]).ravel()
    prec = precision_score(y_test, y_test_pred, zero_division=0)
    rec = recall_score(y_test, y_test_pred, zero_division=0)
    f1 = f1_score(y_test, y_test_pred, zero_division=0)
    fpr = float(fp) / (tn + fp) if (tn + fp) > 0 else 0.0
    
    print("\n==================== TEST SET METRICS ====================")
    print(f"Total Test Instances: {len(y_test)}")
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
        for attack in unique_labels:
            if attack == 'Normal':
                continue
            attack_mask = (label_names_test == attack)
            benign_mask = (y_test == 0)
            sub_mask = attack_mask | benign_mask
            
            sub_y_true = np.where(y_test[sub_mask] == 1, 1, 0)
            sub_y_pred = y_test_pred[sub_mask]
            
            sub_tn, sub_fp, sub_fn, sub_tp = confusion_matrix(sub_y_true, sub_y_pred, labels=[0, 1]).ravel()
            sub_rec = recall_score(sub_y_true, sub_y_pred, zero_division=0)
            print(f"Attack Category: {attack}")
            print(f"  Samples: {sum(attack_mask)} | Detected: {sub_tp} ({sub_rec*100:.2f}%) | Missed: {sub_fn}")
            print("---------------------------------------------------------")
    
    # Save artifacts
    os.makedirs(models_dir, exist_ok=True)
    scaler_path = os.path.join(models_dir, 'autoencoder_scaler.pkl')
    model_path = os.path.join(models_dir, 'autoencoder.pth')
    
    joblib.dump(scaler, scaler_path)
    torch.save(model.state_dict(), model_path)
    print(f"\nSaved Autoencoder to {model_path}")
    print(f"Saved Scaler to {scaler_path}")

if __name__ == '__main__':
    train_and_evaluate('data/processed/features.csv', 'models')
