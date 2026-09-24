import os
import pandas as pd
import numpy as np
from collections import Counter

from capture.pcap_reader import parse_packets
from flow.windowing import process_windows
from flow.aggregator import aggregate_flows
from features.extractor import extract_features
from features.schema import FEATURE_NAMES

def load_clean_ground_truth(gt_path):
    """
    Loads and cleans the ground truth dataset to extract attack times and categories.
    """
    df_gt = pd.read_csv(gt_path, header=None)
    df_gt.columns = ['date', 'time', 'category', 'subcategory', 'description', 'cve_info', 'flow_info']
    
    # Strip whitespace
    for col in df_gt.columns:
        if df_gt[col].dtype == 'object':
            df_gt[col] = df_gt[col].astype(str).str.strip()
            
    # Keep standard dates
    df_gt = df_gt[df_gt['date'].str.match(r'^\d{2}/\d{2}/\d{4}$') == True]
    
    # Standardize Datetime & Unix Timestamps
    df_gt['datetime_str'] = df_gt['date'] + ' ' + df_gt['time']
    df_gt['datetime'] = pd.to_datetime(df_gt['datetime_str'], format='%d/%m/%Y %H:%M:%S', errors='coerce')
    df_gt = df_gt.dropna(subset=['datetime'])
    df_gt['timestamp'] = df_gt['datetime'].astype('int64') // 10**9
    
    return df_gt

def match_window_label(window_start, window_end, df_gt):
    """
    Determines the label of a 5-second window [window_start, window_end).
    Returns (label_code, label_name).
    0 represents Normal. 1 represents Attack.
    """
    # Find all attacks that fell inside this window
    overlapping_attacks = df_gt[(df_gt['timestamp'] >= window_start) & (df_gt['timestamp'] < window_end)]
    
    if overlapping_attacks.empty:
        return 0, 'Normal'
    
    # If there are attacks, assign the category of the most frequent attack (mode)
    categories = overlapping_attacks['category'].tolist()
    most_common_cat = Counter(categories).most_common(1)[0][0]
    
    return 1, most_common_cat

def run_pipeline(pcap_path, gt_path, features_out_path, metadata_out_path, max_packets=None, max_windows=None):
    """
    Runs the complete preprocessing and labeling pipeline on the dataset.
    """
    print("Loading and cleaning ground truth...")
    df_gt = load_clean_ground_truth(gt_path)
    
    print("Starting incremental streaming of PCAP...")
    pkt_generator = parse_packets(pcap_path, max_packets=max_packets)
    window_generator = process_windows(pkt_generator, window_size=5.0)
    
    feature_rows = []
    metadata_rows = []
    
    window_count = 0
    for window in window_generator:
        if max_windows and window_count >= max_windows:
            break
            
        window_start = window['window_start']
        window_end = window['window_end']
        window_id = window['window_id']
        
        # 1. Map labels to this window
        label_code, label_name = match_window_label(window_start, window_end, df_gt)
        
        # 2. Aggregate flows in this window
        aggregated_flows = aggregate_flows(window)
        
        # If window is empty, append a placeholder normal record or continue
        if not aggregated_flows:
            # Produce a default row for an empty window to represent normal state
            empty_record = {k: 0.0 for k in FEATURE_NAMES}
            empty_record['label'] = label_code
            empty_record['label_name'] = label_name
            empty_record['window_id'] = window_id
            feature_rows.append(empty_record)
            
            meta_record = {
                'window_id': window_id, 'window_start': window_start, 'window_end': window_end,
                'src_ip': None, 'dst_ip': None, 'src_port': None, 'dst_port': None, 'protocol': 'NONE'
            }
            metadata_rows.append(meta_record)
        else:
            # Process each flow within the window
            for flow in aggregated_flows:
                feat_dict, meta_dict = extract_features(flow)
                
                # Merge label into both outputs
                feat_dict['label'] = label_code
                feat_dict['label_name'] = label_name
                feat_dict['window_id'] = window_id
                
                meta_dict['label'] = label_code
                meta_dict['label_name'] = label_name
                
                feature_rows.append(feat_dict)
                metadata_rows.append(meta_dict)
                
        window_count += 1
        if window_count % 100 == 0:
            print(f"Processed {window_count} windows...")
            
    # Convert and save datasets
    df_features = pd.DataFrame(feature_rows)
    df_metadata = pd.DataFrame(metadata_rows)
    
    # Enforce order of columns
    feature_cols = FEATURE_NAMES + ['label', 'label_name', 'window_id']
    df_features = df_features[feature_cols]
    
    # Ensure destination parent directories exist
    os.makedirs(os.path.dirname(features_out_path), exist_ok=True)
    os.makedirs(os.path.dirname(metadata_out_path), exist_ok=True)
    
    df_features.to_csv(features_out_path, index=False)
    df_metadata.to_csv(metadata_out_path, index=False)
    
    print(f"Dataset successfully saved!")
    print(f"Features written to: {features_out_path} ({df_features.shape})")
    print(f"Metadata written to: {metadata_out_path} ({df_metadata.shape})")
    
    return df_features, df_metadata
