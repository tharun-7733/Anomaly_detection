import os
import random
import datetime
import time
import threading
import pandas as pd
import numpy as np
import joblib
import psutil
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from live_sniffer import tracker


app = FastAPI(title="NetGuard AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Model", "models")
model_path = os.path.join(MODEL_DIR, "isolation_forest.pkl")
scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")

try:
    clf = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    print("✅ ML Models loaded successfully")
except Exception as e:
    print(f"⚠️ Failed to load ML models: {e}")
    clf = None
    scaler = None

UNSW_COLUMN_MAP = {
    'packets_per_second'     : 'rate',
    'bytes_per_second'       : 'sbytes',      
    'mean_packet_size'       : 'smean',       
    'std_packet_size'        : 'stcpb',       
    'syn_ratio'              : 'synack',      
    'ack_ratio'              : 'ackdat',      
    'rst_ratio'              : 'ct_state_ttl',
    'fin_ratio'              : 'ct_dst_src_ltm',
    'unique_src_ips'         : 'ct_src_ltm',
    'unique_dst_ips'         : 'ct_dst_ltm',
    'unique_src_ports'       : 'ct_src_dport_ltm',
    'unique_dst_ports'       : 'ct_dst_sport_ltm',
    'connection_rate'        : 'ct_srv_src',
    'session_duration'       : 'dur',
}
ORDERED_FEATURES = list(UNSW_COLUMN_MAP.keys())

global_stats = {
    "totalPackets": 0,
    "normalTraffic": 0,
    "anomalies": 0
}

# --- Realtime Monitor ---
realtime_metrics = {
    "rate": 0.0,
    "sbytes": 0.0,
    "smean": 0.0,
    "cpu": 0.0,
    "ram": 0.0
}
traffic_history = []

def monitor_system():
    last_io = psutil.net_io_counters()
    last_time = time.time()
    
    while True:
        time.sleep(2)
        current_io = psutil.net_io_counters()
        current_time = time.time()
        
        dt = current_time - last_time
        d_bytes = current_io.bytes_sent + current_io.bytes_recv - (last_io.bytes_sent + last_io.bytes_recv)
        d_pkts = current_io.packets_sent + current_io.packets_recv - (last_io.packets_sent + last_io.packets_recv)
        
        rate = d_pkts / dt if dt > 0 else 0
        sbytes = d_bytes / dt if dt > 0 else 0
        smean = sbytes / rate if rate > 0 else 0
        
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        
        realtime_metrics["rate"] = rate
        realtime_metrics["sbytes"] = sbytes
        realtime_metrics["smean"] = smean
        realtime_metrics["cpu"] = cpu
        realtime_metrics["ram"] = ram
        
        # Inject artificial anomaly if CPU usage is very high, to make it detectable
        # or we just let the network stats speak for themselves
        
        # Store in traffic history
        normal_pkts = int(rate)
        # We will determine anomaly later, but let's estimate
        t_str = datetime.datetime.now().strftime("%H:%M:%S")
        traffic_history.append({
            "time": t_str,
            "packets": int(rate),
            "normal": int(rate),
            "anomaly": 0 # Will be updated by packet gen
        })
        if len(traffic_history) > 20:
            traffic_history.pop(0)
            
        last_io = current_io
        last_time = current_time

threading.Thread(target=monitor_system, daemon=True).start()
# ------------------------

@app.get("/")
def health_check():
    return {"status": "online", "model": "Isolation Forest"}

@app.get("/api/stats")
def get_stats():
    return {
        **global_stats,
        "cpu": realtime_metrics["cpu"],
        "ram": realtime_metrics["ram"],
        "rate": realtime_metrics["rate"],
        "sbytes": realtime_metrics["sbytes"]
    }

@app.get("/api/packets")
def get_packets(limit: int = 10):
    if clf is None:
        return []
    
    # Try fetching LIVE features from Scapy Sniffer
    live_features = tracker.get_features_and_clear()
    
    if not live_features:
        return []
    
    sample = pd.DataFrame(live_features)
    # Limit if too many
    if len(sample) > limit:
        sample = sample.head(limit)
        
    X_raw = pd.DataFrame()
    for proj_feat, unsw_col in UNSW_COLUMN_MAP.items():
        # Our live sniffer outputs the exact keys of the dictionary
        X_raw[proj_feat] = sample[proj_feat] if proj_feat in sample else 0
        
    # Scale exactly as model expects (using unsw_col order)
    # Actually the order expected by the scaler is ORDERED_FEATURES which are the keys of UNSW_COLUMN_MAP
    # Wait, in the training code, which order was it?
    # Let's map X_raw to ORDERED_FEATURES
    X_raw = X_raw[ORDERED_FEATURES].fillna(0)
    X_scaled = scaler.transform(X_raw)
    
    preds = clf.predict(X_scaled)
    scores = clf.decision_function(X_scaled)
    
    packets_response = []
    anomalies_in_batch = 0
    for i, row in enumerate(sample.itertuples()):
        is_anomaly = preds[i] == -1
        score_percent = max(0, min(100, int((0.15 - scores[i]) * 100))) 
        if is_anomaly:
            score_percent = max(60, score_percent)
            global_stats["anomalies"] += 1
            anomalies_in_batch += 1
            status = "Anomaly"
        else:
            score_percent = min(50, score_percent)
            global_stats["normalTraffic"] += 1
            status = "Normal"
            
        global_stats["totalPackets"] += 1
            
        p_src = getattr(row, "src_ip")
        p_dst = getattr(row, "dst_ip")
        p_proto = getattr(row, "protocol")
        p_sport = getattr(row, "src_port")
        p_dport = getattr(row, "dst_port")
        p_size = int(getattr(row, "mean_packet_size"))

        packets_response.append({
            "id": getattr(row, "id", random.randint(1000, 9999)),
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "src_ip": p_src,
            "dst_ip": p_dst,
            "protocol": p_proto,
            "src_port": p_sport,
            "dst_port": p_dport,
            "packet_size": p_size,
            "status": status,
            "score": score_percent,
            "type": "Detected Attack" if is_anomaly else "Normal",
            "severity": "High" if score_percent > 85 else "Medium" if is_anomaly else "Low",
        })
        
    if traffic_history:
        traffic_history[-1]["anomaly"] = anomalies_in_batch
        traffic_history[-1]["normal"] = max(0, traffic_history[-1]["packets"] - anomalies_in_batch)
        
    return packets_response

@app.get("/api/anomalies")
def get_anomalies():
    packets = get_packets(50)
    return [p for p in packets if p["status"] == "Anomaly"]

@app.get("/api/traffic")
def get_traffic():
    return traffic_history

@app.get("/api/analytics")
def get_analytics():
    return {
        "traffic": get_traffic(),
        "anomalies": get_anomalies()[:5]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
