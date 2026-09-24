def aggregate_flows(window_data):
    """
    Aggregates a list of packets in a single window into 5-tuple flows.
    Input: dict containing 'window_id', 'window_start', 'window_end', and a list of 'packets'.
    """
    flows = {}
    window_start = window_data['window_start']
    window_end = window_data['window_end']
    window_id = window_data['window_id']

    for pkt in window_data['packets']:
        src_ip = pkt['src_ip']
        dst_ip = pkt['dst_ip']
        src_port = pkt['src_port']
        dst_port = pkt['dst_port']
        protocol = pkt['protocol']

        # Standard 5-tuple key
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

        if flow_key not in flows:
            flows[flow_key] = {
                'window_id': window_id,
                'window_start': window_start,
                'window_end': window_end,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'packet_count': 0,
                'byte_count': 0,
                'start_time': pkt['timestamp'],
                'last_time': pkt['timestamp'],
                'syn_count': 0,
                'ack_count': 0,
                'rst_count': 0,
                'fin_count': 0,
                'psh_count': 0,
                'urg_count': 0,
                'packet_sizes': [],
                'payload_sizes': [],
                'timestamps': [],
                'src_ips': set(),
                'dst_ips': set(),
                'src_ports': set(),
                'dst_ports': set(),
                'connection_attempts': 0
            }

        f = flows[flow_key]
        f['packet_count'] += 1
        f['byte_count'] += pkt['size']
        f['start_time'] = min(f['start_time'], pkt['timestamp'])
        f['last_time'] = max(f['last_time'], pkt['timestamp'])
        
        # Flag counts
        f['syn_count'] += pkt['syn']
        f['ack_count'] += pkt['ack']
        f['rst_count'] += pkt['rst']
        f['fin_count'] += pkt['fin']
        f['psh_count'] += pkt['psh']
        f['urg_count'] += pkt['urg']
        
        # Track collection of values
        f['packet_sizes'].append(pkt['size'])
        f['payload_sizes'].append(pkt['payload_size'])
        f['timestamps'].append(pkt['timestamp'])
        if src_ip: f['src_ips'].add(src_ip)
        if dst_ip: f['dst_ips'].add(dst_ip)
        if src_port is not None: f['src_ports'].add(src_port)
        if dst_port is not None: f['dst_ports'].add(dst_port)
        
        # Connection attempts incremented on SYN packet
        if pkt['syn'] == 1:
            f['connection_attempts'] += 1

    # Convert sets to sorted lists/counts for standardization prior to features
    aggregated_list = []
    for flow_key, f in flows.items():
        f['src_ips'] = sorted(list(f['src_ips']))
        f['dst_ips'] = sorted(list(f['dst_ips']))
        f['src_ports'] = sorted(list(f['src_ports']))
        f['dst_ports'] = sorted(list(f['dst_ports']))
        f['timestamps'].sort()
        aggregated_list.append(f)

    return aggregated_list
