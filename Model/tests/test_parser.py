import pytest
from scapy.all import IP, TCP, UDP, ICMP
from capture.pcap_reader import parse_packets
from unittest.mock import patch, MagicMock

@patch('os.path.exists', return_value=True)
def test_packet_parsing_tcp(mock_exists):
    # Construct real Scapy IP/TCP synthetic packet
    pkt = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=1234, dport=80, flags="SA")
    pkt.time = 1000.0

    # Patch PcapReader to yield our synthetic packet
    with patch('capture.pcap_reader.PcapReader') as mock_reader_cls:
        mock_reader = MagicMock()
        mock_reader.__enter__.return_value = [pkt]
        mock_reader_cls.return_value = mock_reader

        parsed = list(parse_packets("dummy.pcap"))

        assert len(parsed) == 1
        p = parsed[0]
        assert p['src_ip'] == "192.168.1.50"
        assert p['dst_ip'] == "10.0.0.1"
        assert p['protocol'] == "TCP"
        assert p['src_port'] == 1234
        assert p['dst_port'] == 80
        assert p['syn'] == 1
        assert p['ack'] == 1
        assert p['rst'] == 0
        assert p['fin'] == 0

@patch('os.path.exists', return_value=True)
def test_packet_parsing_udp_and_icmp(mock_exists):
    # Construct real Scapy IP/UDP and IP/ICMP synthetic packets
    udp_pkt = IP(src="192.168.1.51", dst="10.0.0.2") / UDP(sport=53, dport=5353)
    udp_pkt.time = 1001.0

    icmp_pkt = IP(src="192.168.1.52", dst="10.0.0.3") / ICMP()
    icmp_pkt.time = 1002.0

    with patch('capture.pcap_reader.PcapReader') as mock_reader_cls:
        mock_reader = MagicMock()
        mock_reader.__enter__.return_value = [udp_pkt, icmp_pkt]
        mock_reader_cls.return_value = mock_reader

        parsed = list(parse_packets("dummy.pcap"))

        assert len(parsed) == 2
        # UDP validations
        assert parsed[0]['protocol'] == "UDP"
        assert parsed[0]['src_port'] == 53
        assert parsed[0]['dst_port'] == 5353

        # ICMP validations
        assert parsed[1]['protocol'] == "ICMP"
        assert parsed[1]['src_port'] is None
        assert parsed[1]['dst_port'] is None
