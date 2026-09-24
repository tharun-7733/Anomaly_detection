import pytest
from features.extractor import extract_features
from features.schema import FEATURE_NAMES

def test_feature_ordering_and_values():
    # Mocked aggregated flow data
    flow_record = {
        'window_id': 1,
        'window_start': 10.0,
        'window_end': 15.0,
        'src_ip': '10.0.0.1',
        'dst_ip': '10.0.0.2',
        'src_port': 80,
        'dst_port': 1000,
        'protocol': 'TCP',
        'packet_count': 4,
        'byte_count': 400,
        'start_time': 10.0,
        'last_time': 14.0,
        'syn_count': 1,
        'ack_count': 2,
        'rst_count': 1,
        'fin_count': 0,
        'packet_sizes': [100, 100, 100, 100],
        'src_ips': ['10.0.0.1'],
        'dst_ips': ['10.0.0.2'],
        'src_ports': [80],
        'dst_ports': [1000],
        'connection_attempts': 1
    }
    
    feature_dict, metadata_dict = extract_features(flow_record)
    
    # Check exact layout & length
    assert len(feature_dict) == 14
    assert list(feature_dict.keys()) == FEATURE_NAMES
    
    # Validate specific outputs
    assert feature_dict['flow_duration'] == 4.0
    assert feature_dict['packets_per_second'] == 1.0
    assert feature_dict['bytes_per_second'] == 100.0
    assert feature_dict['syn_ratio'] == 0.25
    assert feature_dict['ack_ratio'] == 0.5
    assert feature_dict['rst_ratio'] == 0.25
    assert feature_dict['fin_ratio'] == 0.0
    assert feature_dict['unique_src_ips'] == 1.0
    assert feature_dict['unique_dst_ips'] == 1.0

def test_division_by_zero_handling():
    # Edge case: zero packets and zero duration
    flow_record = {
        'packet_count': 0,
        'byte_count': 0,
        'start_time': 10.0,
        'last_time': 10.0,
        'syn_count': 0,
        'ack_count': 0,
        'rst_count': 0,
        'fin_count': 0,
        'packet_sizes': [],
        'src_ips': [],
        'dst_ips': [],
        'src_ports': [],
        'dst_ports': [],
        'connection_attempts': 0
    }
    
    feature_dict, _ = extract_features(flow_record)
    
    # No calculations should crash or return NaN/Inf
    for val in feature_dict.values():
        assert isinstance(val, float)
        assert not (val != val)  # Asserts not NaN
        assert val != float('inf')
        assert val != float('-inf')
