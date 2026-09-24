from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
import os

app = FastAPI(title="Network Anomaly Detection API")

# Load models
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
try:
    clf = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
    print("✅ ML Models loaded successfully")
except Exception as e:
    print(f"⚠️ Failed to load ML models: {e}")
    clf = None
    scaler = None

# Feature Schema
class TrafficFeatures(BaseModel):
    packets_per_second: float
    bytes_per_second: float
    mean_packet_size: float
    std_packet_size: float
    syn_ratio: float
    ack_ratio: float
    rst_ratio: float
    fin_ratio: float
    unique_src_ips: int
    unique_dst_ips: int
    unique_src_ports: int
    unique_dst_ports: int
    connection_rate: float
    session_duration: float

# The model requires exactly this order
FEATURE_COLUMNS = [
    'packets_per_second', 'bytes_per_second', 'mean_packet_size', 'std_packet_size',
    'syn_ratio', 'ack_ratio', 'rst_ratio', 'fin_ratio', 'unique_src_ips', 'unique_dst_ips',
    'unique_src_ports', 'unique_dst_ports', 'connection_rate', 'session_duration'
]

@app.get("/")
def read_root():
    return {"message": "Network Anomaly Detection API is running!"}

@app.post("/predict")
def predict_anomaly(features: TrafficFeatures):
    if clf is None or scaler is None:
        raise HTTPException(status_code=500, detail="Models are not loaded.")

    try:
        # Convert input to DataFrame
        data = features.model_dump()
        df = pd.DataFrame([data])
        
        # Ensure correct column order
        df = df[FEATURE_COLUMNS]
        
        # Scale features
        X_scaled = scaler.transform(df)
        
        # Predict
        score = clf.decision_function(X_scaled)[0]
        prediction = clf.predict(X_scaled)[0]
        
        is_anomaly = prediction == -1
        
        return {
            "is_anomaly": bool(is_anomaly),
            "anomaly_score": float(score),
            "severity": "High" if score < -0.1 else ("Medium" if score < 0 else "Low")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
