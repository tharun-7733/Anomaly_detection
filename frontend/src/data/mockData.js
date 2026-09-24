const now = Date.now()

export const initialTraffic = Array.from({ length: 18 }, (_, index) => {
  const packets = 420 + Math.round(Math.sin(index / 2) * 55) + index * 5
  return {
    time: `${String(12 + Math.floor(index / 6)).padStart(2, '0')}:${String((index * 5) % 60).padStart(2, '0')}`,
    packets: Math.max(280, packets),
    normal: Math.max(240, packets - 8 - (index % 4) * 3),
    anomaly: 8 + (index % 5) * 3,
  }
})

export const anomalies = [
  { id: 1, time: '14:32:08', timestamp: '2026-09-24 14:32:08', source: '192.168.1.10', destination: '10.0.0.5', protocol: 'TCP', type: 'DDoS', score: 94, severity: 'Critical', status: 'Investigating', srcPort: 443, dstPort: 62403, packetSize: 1334, reason: 'Sustained packet burst exceeded baseline by 8.4x.' },
  { id: 2, time: '14:31:44', timestamp: '2026-09-24 14:31:44', source: '172.16.0.22', destination: '10.0.0.12', protocol: 'TCP', type: 'Port Scan', score: 81, severity: 'High', status: 'Open', srcPort: 55122, dstPort: 22, packetSize: 74, reason: 'Sequential connection attempts across 32 service ports.' },
  { id: 3, time: '14:30:19', timestamp: '2026-09-24 14:30:19', source: '10.10.4.8', destination: '192.168.1.1', protocol: 'UDP', type: 'Traffic Spike', score: 73, severity: 'Medium', status: 'Review', srcPort: 5353, dstPort: 53, packetSize: 980, reason: 'DNS request volume shows an abnormal short-term spike.' },
  { id: 4, time: '14:28:57', timestamp: '2026-09-24 14:28:57', source: '192.168.1.44', destination: '10.0.0.18', protocol: 'UDP', type: 'Suspicious UDP', score: 62, severity: 'Medium', status: 'Resolved', srcPort: 1900, dstPort: 1900, packetSize: 512, reason: 'Unexpected discovery traffic from a restricted subnet.' },
  { id: 5, time: '14:26:30', timestamp: '2026-09-24 14:26:30', source: '10.0.0.7', destination: '172.16.0.9', protocol: 'TCP', type: 'Abnormal Packet Rate', score: 44, severity: 'Low', status: 'Resolved', srcPort: 443, dstPort: 50412, packetSize: 1460, reason: 'Packet cadence diverges from the learned host profile.' },
]

export const packets = [
  { timestamp: '14:32:08.441', src_ip: '10.171.100.58', dst_ip: '40.79.150.124', protocol: 'TCP', src_port: 62403, dst_port: 443, packet_size: 1334, status: 'Anomaly', score: 94 },
  { timestamp: '14:32:08.390', src_ip: '172.16.0.22', dst_ip: '10.0.0.12', protocol: 'TCP', src_port: 55122, dst_port: 22, packet_size: 74, status: 'Normal', score: 12 },
  { timestamp: '14:32:08.212', src_ip: '10.10.4.8', dst_ip: '192.168.1.1', protocol: 'UDP', src_port: 5353, dst_port: 53, packet_size: 980, status: 'Warning', score: 62 },
  { timestamp: '14:32:07.884', src_ip: '10.0.0.21', dst_ip: '172.16.0.4', protocol: 'TCP', src_port: 443, dst_port: 52044, packet_size: 1460, status: 'Normal', score: 9 },
  { timestamp: '14:32:07.631', src_ip: '192.168.1.44', dst_ip: '10.0.0.18', protocol: 'UDP', src_port: 1900, dst_port: 1900, packet_size: 512, status: 'Warning', score: 58 },
  { timestamp: '14:32:07.400', src_ip: '172.16.0.8', dst_ip: '10.0.0.15', protocol: 'TCP', src_port: 80, dst_port: 60321, packet_size: 1280, status: 'Normal', score: 7 },
  { timestamp: '14:32:07.123', src_ip: '10.0.0.7', dst_ip: '172.16.0.9', protocol: 'TCP', src_port: 443, dst_port: 50412, packet_size: 1460, status: 'Normal', score: 11 },
]

export const stats = { totalPackets: 12458, normalTraffic: 12421, anomalies: 37, criticalThreats: 5 }
export const severityData = [
  { name: 'Normal', value: 86, color: '#42d392' },
  { name: 'Low', value: 7, color: '#55b8ff' },
  { name: 'Medium', value: 4, color: '#eabf55' },
  { name: 'High', value: 2, color: '#f68b4e' },
  { name: 'Critical', value: 1, color: '#f05d5e' },
]
export const protocolData = [
  { name: 'TCP', value: 68, color: '#55b8ff' },
  { name: 'UDP', value: 24, color: '#a78bfa' },
  { name: 'Other', value: 8, color: '#485467' },
]
