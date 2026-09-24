import numpy as np
from features.schema import FEATURE_NAMES

def extract_features(flow_record):
    """
    Calculates the 14 behavioral features for an aggregated flow in a 5-second window.
    Returns a tuple: (feature_dict, metadata_dict)
    """
    # Helper variables from the aggregated flow record
    pkt_count = flow_record.get('packet_count', 0)
    byte_count = flow_record.get('byte_count', 0)
    start_time = flow_record.get('start_time', 0)
    last_time = flow_record.get('last_time', 0)
    syn_count = flow_record.get('syn_count', 0)
    ack_count = flow_record.get('ack_count', 0)
    rst_count = flow_record.get('rst_count', 0)
    fin_count = flow_record.get('fin_count', 0)
    psh_count = flow_record.get('psh_count', 0)
    urg_count = flow_record.get('urg_count', 0)
    
    packet_sizes = flow_record.get('packet_sizes', [])
    payload_sizes = flow_record.get('payload_sizes', [])
    timestamps = flow_record.get('timestamps', [])
    
    src_ips = flow_record.get('src_ips', [])
    dst_ips = flow_record.get('dst_ips', [])
    src_ports = flow_record.get('src_ports', [])
    dst_ports = flow_record.get('dst_ports', [])
    conn_attempts = flow_record.get('connection_attempts', 0)

    # Calculate flow duration
    flow_duration = max(0.0, last_time - start_time)
    # Use a small epsilon to prevent division by zero for rates over flow duration
    time_denom = flow_duration if flow_duration > 0 else 1.0
    
    # 1. packets_per_second
    packets_per_second = float(pkt_count) / time_denom
    
    # 2. bytes_per_second
    bytes_per_second = float(byte_count) / time_denom
    
    # 3. mean_packet_size
    mean_packet_size = float(np.mean(packet_sizes)) if packet_sizes else 0.0
    
    # 4. std_packet_size
    std_packet_size = float(np.std(packet_sizes)) if len(packet_sizes) > 1 else 0.0
    
    # Ratio features (safe division over total packet count)
    pkt_denom = float(pkt_count) if pkt_count > 0 else 1.0
    
    # 5. syn_ratio
    syn_ratio = float(syn_count) / pkt_denom
    
    # 6. ack_ratio
    ack_ratio = float(ack_count) / pkt_denom
    
    # 7. rst_ratio
    rst_ratio = float(rst_count) / pkt_denom
    
    # 8. fin_ratio
    fin_ratio = float(fin_count) / pkt_denom
    
    # 9. psh_ratio
    psh_ratio = float(psh_count) / pkt_denom
    
    # 10. urg_ratio
    urg_ratio = float(urg_count) / pkt_denom
    
    # Payload features
    min_payload_size = float(np.min(payload_sizes)) if payload_sizes else 0.0
    max_payload_size = float(np.max(payload_sizes)) if payload_sizes else 0.0
    mean_payload_size = float(np.mean(payload_sizes)) if payload_sizes else 0.0
    std_payload_size = float(np.std(payload_sizes)) if len(payload_sizes) > 1 else 0.0
    
    # Inter-arrival time (IAT) features
    if len(timestamps) > 1:
        iats = np.diff(timestamps)
        iat_mean = float(np.mean(iats))
        iat_std = float(np.std(iats))
        iat_min = float(np.min(iats))
        iat_max = float(np.max(iats))
    else:
        iat_mean = 0.0
        iat_std = 0.0
        iat_min = 0.0
        iat_max = 0.0
    
    # Unique element counts
    # 9. unique_src_ips
    unique_src_ips = float(len(src_ips))
    
    # 10. unique_dst_ips
    unique_dst_ips = float(len(dst_ips))
    
    # 11. unique_src_ports
    unique_src_ports = float(len(src_ports))
    
    # 12. unique_dst_ports
    unique_dst_ports = float(len(dst_ports))
    
    # 13. connection_rate
    connection_rate = float(conn_attempts) / time_denom
    
    # 14. flow_duration
    # already calculated

    feature_dict = {
        'packets_per_second': packets_per_second,
        'bytes_per_second': bytes_per_second,
        'mean_packet_size': mean_packet_size,
        'std_packet_size': std_packet_size,
        'min_payload_size': min_payload_size,
        'max_payload_size': max_payload_size,
        'mean_payload_size': mean_payload_size,
        'std_payload_size': std_payload_size,
        'iat_mean': iat_mean,
        'iat_std': iat_std,
        'iat_min': iat_min,
        'iat_max': iat_max,
        'syn_ratio': syn_ratio,
        'ack_ratio': ack_ratio,
        'rst_ratio': rst_ratio,
        'fin_ratio': fin_ratio,
        'psh_ratio': psh_ratio,
        'urg_ratio': urg_ratio,
        'unique_src_ips': unique_src_ips,
        'unique_dst_ips': unique_dst_ips,
        'unique_src_ports': unique_src_ports,
        'unique_dst_ports': unique_dst_ports,
        'connection_rate': connection_rate,
        'flow_duration': flow_duration
    }
    
    # Metadata required for investigation/mapping
    metadata_dict = {
        'window_id': flow_record.get('window_id'),
        'window_start': flow_record.get('window_start'),
        'window_end': flow_record.get('window_end'),
        'src_ip': flow_record.get('src_ip'),
        'dst_ip': flow_record.get('dst_ip'),
        'src_port': flow_record.get('src_port'),
        'dst_port': flow_record.get('dst_port'),
        'protocol': flow_record.get('protocol')
    }
    
    return feature_dict, metadata_dict
