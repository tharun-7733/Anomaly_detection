import sys

with open("api.py", "r") as f:
    content = f.read()

# Add import
import_stmt = "from live_sniffer import tracker\n"
if "from live_sniffer" not in content:
    content = content.replace("from pydantic import BaseModel", "from pydantic import BaseModel\n" + import_stmt)

# Replace get_packets
target_start = "@app.get(\"/api/packets\")"
target_end = "@app.get(\"/api/anomalies\")"

start_idx = content.find(target_start)
end_idx = content.find(target_end)

new_get_packets = """@app.get("/api/packets")
def get_packets(limit: int = 10):
    if clf is None:
        return []
    
    # Try fetching LIVE features from Scapy Sniffer
    live_features = tracker.get_features_and_clear()
    
    using_live = len(live_features) > 0
    
    if using_live:
        sample = pd.DataFrame(live_features)
        # Limit if too many
        if len(sample) > limit:
            sample = sample.head(limit)
    else:
        if df is None:
            return []
        sample = df.sample(limit).copy()
        
        # Overwrite rate and bytes with real system aggregate data
        base_rate = realtime_metrics["rate"]
        base_sbytes = realtime_metrics["sbytes"]
        base_smean = realtime_metrics["smean"]
        
        if realtime_metrics["cpu"] > 80:
            base_rate *= 10
            base_sbytes *= 10
        
        sample['rate'] = [base_rate * random.uniform(0.8, 1.2) for _ in range(limit)]
        sample['sbytes'] = [base_sbytes * random.uniform(0.8, 1.2) for _ in range(limit)]
        sample['smean'] = [base_smean * random.uniform(0.8, 1.2) for _ in range(limit)]
        
    X_raw = pd.DataFrame()
    for proj_feat, unsw_col in UNSW_COLUMN_MAP.items():
        if using_live:
            # Our live sniffer outputs the exact keys of the dictionary
            X_raw[proj_feat] = sample[proj_feat] if proj_feat in sample else 0
        else:
            # Mock data uses the unsw_col names
            X_raw[proj_feat] = sample[unsw_col]
        
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
            
        if using_live:
            p_src = getattr(row, "src_ip")
            p_dst = getattr(row, "dst_ip")
            p_proto = getattr(row, "protocol")
            p_sport = getattr(row, "src_port")
            p_dport = getattr(row, "dst_port")
            p_size = int(getattr(row, "mean_packet_size"))
        else:
            p_src = random.choice(MOCK_IPS)
            p_dst = random.choice(MOCK_IPS)
            p_proto = getattr(row, "proto", "TCP").upper()
            p_sport = random.randint(1024, 65535)
            p_dport = random.choice([80, 443, 22, 53, 3389])
            p_size = int(sample['smean'].iloc[i] if sample['smean'].iloc[i] > 0 else getattr(row, "sbytes", random.randint(100, 1500)))

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
            "type": getattr(row, "attack_cat", "Normal") if (not using_live and is_anomaly) else ("Detected Attack" if is_anomaly else "Normal"),
            "severity": "High" if score_percent > 85 else "Medium" if is_anomaly else "Low",
        })
        
    if traffic_history:
        traffic_history[-1]["anomaly"] = anomalies_in_batch
        traffic_history[-1]["normal"] = max(0, traffic_history[-1]["packets"] - anomalies_in_batch)
        
    return packets_response

"""

content = content[:start_idx] + new_get_packets + content[end_idx:]

with open("api.py", "w") as f:
    f.write(content)
