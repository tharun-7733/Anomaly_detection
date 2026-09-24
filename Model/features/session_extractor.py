import numpy as np
from features.session_schema import SESSION_FEATURE_NAMES

def extract_session_features(session):
    """
    Extracts per-session features from a closed TCP/UDP session dict.
    Returns (feature_dict, metadata_dict).
    """
    fwd_pkts = session.get('fwd_packets', [])   # list of (timestamp, size, payload_size, flags)
    bwd_pkts = session.get('bwd_packets', [])

    all_pkts = sorted(fwd_pkts + bwd_pkts, key=lambda x: x[0])
    timestamps = [p[0] for p in all_pkts]
    payload_sizes = [p[2] for p in all_pkts]

    total_packets = len(all_pkts)
    fwd_n = len(fwd_pkts)
    bwd_n = len(bwd_pkts)

    total_bytes = sum(p[1] for p in all_pkts)
    fwd_bytes = sum(p[1] for p in fwd_pkts)
    bwd_bytes = sum(p[1] for p in bwd_pkts)

    # Duration
    if len(timestamps) >= 2:
        session_duration = timestamps[-1] - timestamps[0]
    else:
        session_duration = 0.0
    time_denom = session_duration if session_duration > 0 else 1.0

    # Rates
    packets_per_second = total_packets / time_denom
    bytes_per_second = total_bytes / time_denom

    # Ratios
    bytes_ratio = fwd_bytes / (total_bytes + 1e-9)
    pkt_ratio = fwd_n / (total_packets + 1e-9)

    # Payload stats
    if payload_sizes:
        mean_payload_size = float(np.mean(payload_sizes))
        std_payload_size = float(np.std(payload_sizes)) if len(payload_sizes) > 1 else 0.0
        max_payload_size = float(np.max(payload_sizes))
        min_payload_size = float(np.min(payload_sizes))
    else:
        mean_payload_size = std_payload_size = max_payload_size = min_payload_size = 0.0

    # IAT
    if len(timestamps) > 1:
        iats = np.diff(timestamps)
        iat_mean = float(np.mean(iats))
        iat_std = float(np.std(iats))
        iat_min = float(np.min(iats))
        iat_max = float(np.max(iats))
    else:
        iat_mean = iat_std = iat_min = iat_max = 0.0

    # TCP flags (summed across all packets)
    syn_count = session.get('syn_count', 0)
    fin_count = session.get('fin_count', 0)
    rst_count = session.get('rst_count', 0)
    psh_count = session.get('psh_count', 0)
    urg_count = session.get('urg_count', 0)
    ack_count = session.get('ack_count', 0)
    fwd_psh_count = session.get('fwd_psh_count', 0)

    syn_fin_ratio = syn_count / (fin_count + 1.0)
    rst_ratio = rst_count / (total_packets + 1e-9)
    fwd_psh_ratio = fwd_psh_count / (fwd_n + 1e-9)

    # Handshake: we consider it complete if we saw SYN + SYN-ACK (tracked externally)
    handshake_complete = float(session.get('handshake_complete', 0))

    feature_dict = {
        'session_duration': session_duration,
        'total_packets': float(total_packets),
        'fwd_packets': float(fwd_n),
        'bwd_packets': float(bwd_n),
        'total_bytes': float(total_bytes),
        'fwd_bytes': float(fwd_bytes),
        'bwd_bytes': float(bwd_bytes),
        'bytes_ratio': bytes_ratio,
        'pkt_ratio': pkt_ratio,
        'mean_payload_size': mean_payload_size,
        'std_payload_size': std_payload_size,
        'max_payload_size': max_payload_size,
        'min_payload_size': min_payload_size,
        'packets_per_second': packets_per_second,
        'bytes_per_second': bytes_per_second,
        'iat_mean': iat_mean,
        'iat_std': iat_std,
        'iat_min': iat_min,
        'iat_max': iat_max,
        'syn_count': float(syn_count),
        'fin_count': float(fin_count),
        'rst_count': float(rst_count),
        'psh_count': float(psh_count),
        'urg_count': float(urg_count),
        'ack_count': float(ack_count),
        'syn_fin_ratio': syn_fin_ratio,
        'rst_ratio': rst_ratio,
        'handshake_complete': handshake_complete,
        'fwd_psh_ratio': fwd_psh_ratio,
    }

    metadata_dict = {
        'session_id': session.get('session_id'),
        'src_ip': session.get('src_ip'),
        'dst_ip': session.get('dst_ip'),
        'src_port': session.get('src_port'),
        'dst_port': session.get('dst_port'),
        'protocol': session.get('protocol'),
        'start_time': session.get('start_time'),
        'end_time': session.get('end_time'),
    }

    return feature_dict, metadata_dict
