import pytest
from flow.windowing import process_windows
from flow.aggregator import aggregate_flows

def test_window_creation_and_empty():
    # Test window boundary assignment
    packets = [
        {"timestamp": 10.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 80, "dst_port": 1000, "protocol": "TCP", "size": 100, "syn": 1, "ack": 0, "rst": 0, "fin": 0},
        {"timestamp": 14.9, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 80, "dst_port": 1000, "protocol": "TCP", "size": 200, "syn": 0, "ack": 1, "rst": 0, "fin": 0},
        # This packet jumps over window 1 (15.0 - 20.0) into window 2 (20.0 - 25.0)
        {"timestamp": 21.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 80, "dst_port": 1000, "protocol": "TCP", "size": 300, "syn": 0, "ack": 0, "rst": 0, "fin": 1}
    ]
    
    windows = list(process_windows(packets, window_size=5.0))
    
    # We expect 3 windows: [10.0 - 15.0], [15.0 - 20.0] (empty), and [20.0 - 25.0]
    assert len(windows) == 3
    
    assert windows[0]["window_start"] == 10.0
    assert windows[0]["window_end"] == 15.0
    assert len(windows[0]["packets"]) == 2
    
    assert windows[1]["window_start"] == 15.0
    assert windows[1]["window_end"] == 20.0
    assert len(windows[1]["packets"]) == 0  # Handles empty windows correctly
    
    assert windows[2]["window_start"] == 20.0
    assert windows[2]["window_end"] == 25.0
    assert len(windows[2]["packets"]) == 1

def test_packet_aggregation_multiple_flows():
    window_data = {
        "window_id": 1,
        "window_start": 10.0,
        "window_end": 15.0,
        "packets": [
            # Flow 1
            {"timestamp": 11.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 80, "dst_port": 1000, "protocol": "TCP", "size": 60, "syn": 1, "ack": 0, "rst": 0, "fin": 0},
            # Flow 2
            {"timestamp": 12.0, "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "src_port": 443, "dst_port": 2000, "protocol": "TCP", "size": 80, "syn": 1, "ack": 0, "rst": 0, "fin": 0},
            # Flow 1 again
            {"timestamp": 13.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 80, "dst_port": 1000, "protocol": "TCP", "size": 120, "syn": 0, "ack": 1, "rst": 0, "fin": 0}
        ]
    }
    
    flows = aggregate_flows(window_data)
    assert len(flows) == 2
    
    # Flow 1 validations
    flow1 = next(f for f in flows if f["src_ip"] == "10.0.0.1")
    assert flow1["packet_count"] == 2
    assert flow1["byte_count"] == 180
    assert flow1["syn_count"] == 1
    assert flow1["ack_count"] == 1
    assert flow1["start_time"] == 11.0
    assert flow1["last_time"] == 13.0
