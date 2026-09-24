import argparse
from pipeline.prepare_dataset import run_pipeline

def main():
    parser = argparse.ArgumentParser(description="Anomaly Detection - Data Preparation Pipeline")
    parser.add_argument('--pcap', type=str, required=True, help="Path to the input PCAP file")
    parser.add_argument('--gt', type=str, required=True, help="Path to the ground truth CSV file")
    parser.add_argument('--out-features', type=str, default='data/processed/features.csv', help="Output path for features CSV")
    parser.add_argument('--out-metadata', type=str, default='data/processed/metadata.csv', help="Output path for metadata CSV")
    parser.add_argument('--max-packets', type=int, default=None, help="Maximum number of packets to process (for testing)")
    parser.add_argument('--max-windows', type=int, default=None, help="Maximum number of windows to process (for testing)")
    
    args = parser.parse_args()
    
    print("Starting pipeline...")
    run_pipeline(
        pcap_path=args.pcap,
        gt_path=args.gt,
        features_out_path=args.out_features,
        metadata_out_path=args.out_metadata,
        max_packets=args.max_packets,
        max_windows=args.max_windows
    )
    print("Pipeline finished successfully.")

if __name__ == '__main__':
    main()
