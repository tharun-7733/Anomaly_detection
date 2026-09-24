import gradio as gr
import joblib
import pandas as pd
import os

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

FEATURE_COLUMNS = [
    'packets_per_second', 'bytes_per_second', 'mean_packet_size', 'std_packet_size',
    'syn_ratio', 'ack_ratio', 'rst_ratio', 'fin_ratio', 'unique_src_ips', 'unique_dst_ips',
    'unique_src_ports', 'unique_dst_ports', 'connection_rate', 'session_duration'
]

def predict_anomaly(
    packets_per_second, bytes_per_second, mean_packet_size, std_packet_size,
    syn_ratio, ack_ratio, rst_ratio, fin_ratio, unique_src_ips, unique_dst_ips,
    unique_src_ports, unique_dst_ports, connection_rate, session_duration
):
    if clf is None or scaler is None:
        return "Error: Models are not loaded."
        
    data = {
        'packets_per_second': packets_per_second, 'bytes_per_second': bytes_per_second,
        'mean_packet_size': mean_packet_size, 'std_packet_size': std_packet_size,
        'syn_ratio': syn_ratio, 'ack_ratio': ack_ratio, 'rst_ratio': rst_ratio, 'fin_ratio': fin_ratio,
        'unique_src_ips': unique_src_ips, 'unique_dst_ips': unique_dst_ips,
        'unique_src_ports': unique_src_ports, 'unique_dst_ports': unique_dst_ports,
        'connection_rate': connection_rate, 'session_duration': session_duration
    }
    
    df = pd.DataFrame([data])[FEATURE_COLUMNS]
    X_scaled = scaler.transform(df)
    
    score = clf.decision_function(X_scaled)[0]
    prediction = clf.predict(X_scaled)[0]
    
    is_anomaly = prediction == -1
    severity = "🔴 High" if score < -0.1 else ("🟠 Medium" if score < 0 else "🟢 Low")
    
    if is_anomaly:
        return f"🚨 ANOMALY DETECTED! \nSeverity: {severity}\nAnomaly Score: {score:.4f}"
    else:
        return f"✅ NORMAL TRAFFIC \nSeverity: {severity}\nAnomaly Score: {score:.4f}"

# Define Gradio Interface
inputs = [
    gr.Number(label="Packets per Second", value=100.0),
    gr.Number(label="Bytes per Second", value=15000.0),
    gr.Number(label="Mean Packet Size", value=150.0),
    gr.Number(label="Std Packet Size", value=50.0),
    gr.Number(label="SYN Ratio", value=0.1),
    gr.Number(label="ACK Ratio", value=0.8),
    gr.Number(label="RST Ratio", value=0.0),
    gr.Number(label="FIN Ratio", value=0.01),
    gr.Number(label="Unique Source IPs", value=5),
    gr.Number(label="Unique Dest IPs", value=2),
    gr.Number(label="Unique Source Ports", value=10),
    gr.Number(label="Unique Dest Ports", value=5),
    gr.Number(label="Connection Rate", value=2.5),
    gr.Number(label="Session Duration", value=60.0),
]

app = gr.Interface(
    fn=predict_anomaly,
    inputs=inputs,
    outputs=gr.Textbox(label="Prediction Result"),
    title="NetGuard AI - Anomaly Detection",
    description="Enter network traffic features to detect anomalies using the Isolation Forest model. This interface also provides a free REST API!",
    allow_flagging="never"
)

if __name__ == "__main__":
    app.launch()
