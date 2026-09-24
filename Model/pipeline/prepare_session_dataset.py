import os
import pandas as pd
import numpy as np
from collections import Counter

from capture.pcap_reader import parse_packets
from flow.session_tracker import track_sessions
from features.session_extractor import extract_session_features
from features.session_schema import SESSION_FEATURE_NAMES


def load_clean_ground_truth(gt_path):
    df_gt = pd.read_csv(gt_path, header=None)
    df_gt.columns = ['date', 'time', 'category', 'subcategory', 'description', 'cve_info', 'flow_info']
    for col in df_gt.columns:
        if df_gt[col].dtype == 'object':
            df_gt[col] = df_gt[col].astype(str).str.strip()
    df_gt = df_gt[df_gt['date'].str.match(r'^\d{2}/\d{2}/\d{4}$') == True]
    df_gt['datetime_str'] = df_gt['date'] + ' ' + df_gt['time']
    df_gt['datetime'] = pd.to_datetime(df_gt['datetime_str'], format='%d/%m/%Y %H:%M:%S', errors='coerce')
    df_gt = df_gt.dropna(subset=['datetime'])
    df_gt['timestamp'] = df_gt['datetime'].astype('int64') // 10**9
    return df_gt


def match_session_label(start_time, end_time, df_gt):
    """
    Returns (label_code, label_name) for a session.
    If any attack event falls within the session's time range, label as attack.
    """
    overlapping = df_gt[(df_gt['timestamp'] >= start_time) & (df_gt['timestamp'] <= end_time)]
    if overlapping.empty:
        return 0, 'Normal'
    categories = overlapping['category'].tolist()
    most_common = Counter(categories).most_common(1)[0][0]
    return 1, most_common


def run_session_pipeline(pcap_path, gt_path, features_out_path, metadata_out_path, max_packets=None):
    print("Loading and cleaning ground truth...")
    df_gt = load_clean_ground_truth(gt_path)

    print("Streaming PCAP and tracking sessions...")
    pkt_gen = parse_packets(pcap_path, max_packets=max_packets)
    session_gen = track_sessions(pkt_gen)

    feature_rows = []
    metadata_rows = []
    session_count = 0

    for session in session_gen:
        start_time = session.get('start_time', 0)
        end_time = session.get('end_time', 0)

        # Skip empty sessions (no packets)
        if not session.get('fwd_packets') and not session.get('bwd_packets'):
            continue

        label_code, label_name = match_session_label(start_time, end_time, df_gt)

        feat_dict, meta_dict = extract_session_features(session)
        feat_dict['label'] = label_code
        feat_dict['label_name'] = label_name
        feat_dict['session_id'] = session.get('session_id')

        meta_dict['label'] = label_code
        meta_dict['label_name'] = label_name

        feature_rows.append(feat_dict)
        metadata_rows.append(meta_dict)

        session_count += 1
        if session_count % 50000 == 0:
            print(f"Processed {session_count} sessions...")

    print(f"\nTotal sessions extracted: {session_count}")

    df_features = pd.DataFrame(feature_rows)
    df_metadata = pd.DataFrame(metadata_rows)

    # Enforce column order
    feature_cols = SESSION_FEATURE_NAMES + ['label', 'label_name', 'session_id']
    df_features = df_features[feature_cols]

    os.makedirs(os.path.dirname(features_out_path), exist_ok=True)
    os.makedirs(os.path.dirname(metadata_out_path), exist_ok=True)

    df_features.to_csv(features_out_path, index=False)
    df_metadata.to_csv(metadata_out_path, index=False)

    print(f"Features written to: {features_out_path} {df_features.shape}")
    print(f"Metadata written to: {metadata_out_path} {df_metadata.shape}")

    # Show class distribution
    n_attack = int(df_features['label'].sum())
    n_benign = len(df_features) - n_attack
    print(f"\nClass Distribution:")
    print(f"  Benign sessions: {n_benign}")
    print(f"  Attack sessions: {n_attack} ({n_attack / len(df_features) * 100:.2f}%)")

    return df_features, df_metadata


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', required=True)
    parser.add_argument('--gt', required=True)
    parser.add_argument('--out-features', default='data/sessions/features.csv')
    parser.add_argument('--out-metadata', default='data/sessions/metadata.csv')
    parser.add_argument('--max-packets', type=int, default=None)
    args = parser.parse_args()

    run_session_pipeline(
        pcap_path=args.pcap,
        gt_path=args.gt,
        features_out_path=args.out_features,
        metadata_out_path=args.out_metadata,
        max_packets=args.max_packets
    )
