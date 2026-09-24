"""
Session tracker: groups raw packets into TCP/UDP sessions.

A session is defined by its 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
Bi-directional: the reversed 5-tuple maps back to the same session.

Sessions are closed when:
  - A FIN or RST flag is seen (TCP)
  - The session has been inactive for SESSION_TIMEOUT seconds
  - The PCAP ends (all remaining open sessions are flushed)
"""

SESSION_TIMEOUT = 60.0    # seconds of inactivity before a session is considered closed
UDP_TIMEOUT = 30.0        # shorter timeout for stateless UDP


def _make_key(src_ip, dst_ip, src_port, dst_port, protocol):
    """Canonical bidirectional session key."""
    ep1 = (src_ip, src_port)
    ep2 = (dst_ip, dst_port)
    if ep1 > ep2:
        ep1, ep2 = ep2, ep1
    return (ep1, ep2, protocol)


def track_sessions(packet_gen):
    """
    Generator that consumes a stream of parsed packet dicts and yields
    completed session dicts, one session at a time.

    Each yielded session dict contains:
        session_id, src_ip, dst_ip, src_port, dst_port, protocol,
        start_time, end_time,
        fwd_packets, bwd_packets  (each: list of (timestamp, size, payload_size, flags_dict)),
        syn_count, fin_count, rst_count, psh_count, urg_count, ack_count,
        fwd_psh_count, handshake_complete
    """
    open_sessions = {}    # key -> session dict
    session_counter = 0

    def _new_session(key, pkt, session_id):
        src_ip, dst_ip = pkt['src_ip'], pkt['dst_ip']
        src_port, dst_port = pkt['src_port'], pkt['dst_port']
        return {
            'session_id': session_id,
            'key': key,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': pkt['protocol'],
            'start_time': pkt['timestamp'],
            'end_time': pkt['timestamp'],
            'fwd_packets': [],      # forward direction: original src -> dst
            'bwd_packets': [],      # backward direction: dst -> src
            'syn_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'psh_count': 0,
            'urg_count': 0,
            'ack_count': 0,
            'fwd_psh_count': 0,
            'handshake_complete': 0,
            'saw_syn': False,
            'saw_syn_ack': False,
            '_last_seen': pkt['timestamp'],
            '_closed': False,
        }

    def _add_packet(session, pkt):
        ts = pkt['timestamp']
        size = pkt['size']
        payload = pkt.get('payload_size', 0)
        is_forward = (pkt['src_ip'] == session['src_ip'] and
                      pkt['src_port'] == session['src_port'])

        pkt_tuple = (ts, size, payload)
        if is_forward:
            session['fwd_packets'].append(pkt_tuple)
        else:
            session['bwd_packets'].append(pkt_tuple)

        # Accumulate TCP flags
        session['syn_count'] += pkt.get('syn', 0)
        session['fin_count'] += pkt.get('fin', 0)
        session['rst_count'] += pkt.get('rst', 0)
        session['psh_count'] += pkt.get('psh', 0)
        session['urg_count'] += pkt.get('urg', 0)
        session['ack_count'] += pkt.get('ack', 0)
        if is_forward:
            session['fwd_psh_count'] += pkt.get('psh', 0)

        # Track handshake: SYN seen, then SYN+ACK from server
        if pkt.get('syn') and not pkt.get('ack') and is_forward:
            session['saw_syn'] = True
        if pkt.get('syn') and pkt.get('ack') and not is_forward and session['saw_syn']:
            session['saw_syn_ack'] = True
        if session['saw_syn'] and session['saw_syn_ack']:
            session['handshake_complete'] = 1

        session['end_time'] = max(session['end_time'], ts)
        session['_last_seen'] = ts

    def _close_session(session):
        """Strip internal tracking keys before yielding."""
        for internal_key in ['key', 'saw_syn', 'saw_syn_ack', '_last_seen', '_closed']:
            session.pop(internal_key, None)
        return session

    for pkt in packet_gen:
        ts = pkt['timestamp']
        src_ip = pkt['src_ip']
        dst_ip = pkt['dst_ip']
        src_port = pkt['src_port']
        dst_port = pkt['dst_port']
        protocol = pkt['protocol']

        # Timeout-close stale sessions
        stale_keys = [
            k for k, s in open_sessions.items()
            if ts - s['_last_seen'] > (UDP_TIMEOUT if s['protocol'] == 'UDP' else SESSION_TIMEOUT)
        ]
        for k in stale_keys:
            yield _close_session(open_sessions.pop(k))

        key = _make_key(src_ip, dst_ip, src_port, dst_port, protocol)

        if key not in open_sessions:
            session_counter += 1
            open_sessions[key] = _new_session(key, pkt, session_counter)

        session = open_sessions[key]
        _add_packet(session, pkt)

        # RST closes the session immediately
        if pkt.get('rst', 0):
            yield _close_session(open_sessions.pop(key))
            continue

        # FIN+ACK from both sides closes the session
        # Simplified: close when FIN count >= 2 (both sides sent FIN)
        if protocol == 'TCP' and session['fin_count'] >= 2:
            yield _close_session(open_sessions.pop(key))

    # Flush all remaining open sessions at end of PCAP
    for session in open_sessions.values():
        yield _close_session(session)
