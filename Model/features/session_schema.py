import numpy as np

SESSION_FEATURE_NAMES = [
    # Volume features
    'session_duration',
    'total_packets',
    'fwd_packets',
    'bwd_packets',
    'total_bytes',
    'fwd_bytes',
    'bwd_bytes',
    'bytes_ratio',           # fwd_bytes / total_bytes — large upload = exploit
    'pkt_ratio',             # fwd_packets / total_packets

    # Payload features
    'mean_payload_size',
    'std_payload_size',
    'max_payload_size',
    'min_payload_size',

    # Rate features
    'packets_per_second',
    'bytes_per_second',

    # IAT features
    'iat_mean',
    'iat_std',
    'iat_min',
    'iat_max',

    # TCP Flag features
    'syn_count',
    'fin_count',
    'rst_count',
    'psh_count',
    'urg_count',
    'ack_count',
    'syn_fin_ratio',         # SYN storms: high syn, low fin
    'rst_ratio',             # RST floods

    # Handshake features
    'handshake_complete',    # 0 or 1 — SYN scans won't complete
    'fwd_psh_ratio',         # PSH rate in forward direction
]
