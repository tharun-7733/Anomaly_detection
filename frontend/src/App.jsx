import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertOctagon, BarChart3, Bell, ChevronRight, CircleUserRound, Cpu, Database,
  FileWarning, Gauge, LayoutDashboard, Menu, Network, Search, Settings, ShieldCheck, SlidersHorizontal,
  Table2, X, Zap,
} from 'lucide-react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { getAnalytics, getAnomalies, getDashboardStats, getPackets, getTraffic } from './services/api'
import NetworkTopology from './components/NetworkTopology'

const navItems = [
  { label: 'Dashboard', icon: LayoutDashboard, route: 'dashboard' },
  { label: 'Live Monitoring', icon: Activity, route: 'monitoring' },
  { label: 'Anomalies', icon: AlertOctagon, route: 'anomalies' },
  { label: 'Analytics', icon: BarChart3, route: 'analytics' },
  { label: 'Network Traffic', icon: Network, route: 'traffic' },
]

const formatNumber = (value) => new Intl.NumberFormat('en-US').format(value)
const severityClass = (severity) => `severity severity-${severity.toLowerCase()}`

function App() {
  const [route, setRoute] = useState(window.location.hash.replace('#/', '') || 'dashboard')
  const [stats, setStats] = useState(null)
  const [traffic, setTraffic] = useState([])
  const [anomalies, setAnomalies] = useState([])
  const [packets, setPackets] = useState([])
  const [analytics, setAnalytics] = useState(null)
  const [mobileNav, setMobileNav] = useState(false)
  const [selectedAnomaly, setSelectedAnomaly] = useState(null)

  useEffect(() => {
    Promise.all([getDashboardStats(), getTraffic(), getAnomalies(), getPackets(), getAnalytics()])
      .then(([dashboardStats, liveTraffic, liveAnomalies, livePackets, analyticsData]) => {
        setStats(dashboardStats); setTraffic(liveTraffic); setAnomalies(liveAnomalies); setPackets(livePackets); setAnalytics(analyticsData)
      })
    const onHashChange = () => { setRoute(window.location.hash.replace('#/', '') || 'dashboard'); setMobileNav(false) }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  useEffect(() => {
    if (!stats) return undefined
    const timer = setInterval(() => {
      setTraffic((current) => {
        const last = current[current.length - 1] || { packets: 420, normal: 405, anomaly: 15 }
        const anomaly = Math.max(5, Math.round(last.anomaly + (Math.random() * 10 - 4)))
        const packetsPerSecond = Math.max(260, Math.round(last.packets + (Math.random() * 50 - 25)))
        const next = { time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), packets: packetsPerSecond, normal: packetsPerSecond - anomaly, anomaly }
        return [...current.slice(-17), next]
      })
      setPackets((current) => [{ timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }), src_ip: '10.171.100.58', dst_ip: '40.79.150.124', protocol: Math.random() > .25 ? 'TCP' : 'UDP', src_port: 62403, dst_port: 443, packet_size: 900 + Math.round(Math.random() * 560), status: Math.random() > .88 ? 'Warning' : 'Normal', score: Math.random() > .88 ? 60 + Math.round(Math.random() * 25) : 5 + Math.round(Math.random() * 20) }, ...current].slice(0, 8))
      setStats((current) => ({ ...current, totalPackets: current.totalPackets + Math.round(Math.random() * 12), normalTraffic: current.normalTraffic + Math.round(Math.random() * 10) }))
    }, 3500)
    return () => clearInterval(timer)
  }, [stats])

  if (!stats || !analytics) return <div className="loading-screen"><ShieldCheck size={30} /><span>Initializing secure telemetry...</span></div>

  const pageTitle = navItems.find((item) => item.route === route)?.label || 'Dashboard'
  return (
    <div className="app-shell">
      <Sidebar route={route} mobileNav={mobileNav} onClose={() => setMobileNav(false)} />
      <main className="main-content">
        <Header title={pageTitle} onMenu={() => setMobileNav(true)} />
        <div className="page-content">
          {route === 'dashboard' && <Dashboard stats={stats} traffic={traffic} anomalies={anomalies} />}
          {route === 'monitoring' && <Monitoring traffic={traffic} packets={packets} stats={stats} />}
          {route === 'anomalies' && <Anomalies anomalies={anomalies} onSelect={setSelectedAnomaly} />}
          {route === 'analytics' && <Analytics analytics={analytics} stats={stats} />}
          {route === 'traffic' && <TrafficTable packets={packets} />}
          {route === 'settings' && <SettingsPage />}
        </div>
      </main>
      {selectedAnomaly && <AnomalyModal anomaly={selectedAnomaly} onClose={() => setSelectedAnomaly(null)} />}
    </div>
  )
}

function Sidebar({ route, mobileNav, onClose }) {
  return <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
    <div className="brand"><div className="brand-mark"><ShieldCheck size={20} /></div><div><strong>NetGuard<span> AI</span></strong><small>NETWORK DEFENSE</small></div><button className="icon-button sidebar-close" onClick={onClose}><X size={17} /></button></div>
    <div className="nav-section-label">COMMAND RAIL</div>
    <nav>{navItems.map(({ label, icon: Icon, route: target }) => <a href={`#/${target}`} className={`nav-item ${route === target ? 'active' : ''}`} key={target}><Icon size={16} /><span>{label}</span>{route === target && <ChevronRight className="nav-chevron" size={13} />}</a>)}</nav>
    <div className="nav-section-label nav-section-lower">SYSTEM</div>
    <a href="#/settings" className={`nav-item ${route === 'settings' ? 'active' : ''}`}><Settings size={16} /><span>Settings</span></a>
    <div className="sidebar-footer"><div className="status-block"><span className="live-dot" /> <span>System operational</span><strong>99.99%</strong></div><div className="sensor-row"><Database size={13} /> <span>Sensor cluster</span><span className="status-online">ONLINE</span></div><div className="sensor-row"><Cpu size={13} /> <span>Inference engine</span><span className="status-online">READY</span></div></div>
  </aside>
}

function Header({ title, onMenu }) {
  return <header className="top-header"><button className="icon-button menu-button" onClick={onMenu}><Menu size={20} /></button><div><p className="eyebrow">NETGUARD AI // SOC CONSOLE</p><h1>{title === 'Dashboard' ? 'Network Intelligence' : title}</h1></div><div className="header-actions"><div className="system-live"><span className="live-dot" /> PERIMETER LIVE</div><button className="icon-button notification"><Bell size={17} /><i /></button><div className="profile"><div className="avatar">JD</div><div><strong>J. Doe</strong><span>Analyst</span></div></div></div></header>
}

function StatCard({ label, value, detail, icon: Icon, accent }) {
  return <div className={`stat-card ${accent}`}><div className="stat-card-top"><span>{label}</span><div className="stat-icon"><Icon size={16} /></div></div><strong>{value}</strong><div className="stat-detail">{detail}</div></div>
}

function SectionHeader({ eyebrow, title, action }) { return <div className="section-header"><div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2></div>{action}</div> }
function ChartTooltip({ active, payload, label }) { if (!active || !payload?.length) return null; return <div className="chart-tooltip"><strong>{label}</strong>{payload.map((item) => <span key={item.name}><i style={{ background: item.color }} />{item.name}: <b>{item.value}</b></span>)}</div> }

function TrafficChart({ data, compact = false }) {
  return <ResponsiveContainer width="100%" height={compact ? 220 : 290}><AreaChart data={data} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}><defs><linearGradient id="normalFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#818cf8" stopOpacity=".28" /><stop offset="100%" stopColor="#818cf8" stopOpacity="0" /></linearGradient><linearGradient id="anomalyFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ef4444" stopOpacity=".28" /><stop offset="100%" stopColor="#ef4444" stopOpacity="0" /></linearGradient></defs><CartesianGrid stroke="#1e1b4b" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="time" stroke="#64748b" tickLine={false} axisLine={false} fontSize={10} /><YAxis stroke="#64748b" tickLine={false} axisLine={false} fontSize={10} /><Tooltip content={<ChartTooltip />} /><Legend iconType="circle" wrapperStyle={{ fontSize: 10, color: '#94a3b8', paddingTop: 10 }} /><Area type="monotone" dataKey="normal" name="Normal traffic" stroke="#818cf8" strokeWidth={2} fill="url(#normalFill)" /><Area type="monotone" dataKey="anomaly" name="Anomalous traffic" stroke="#ef4444" strokeWidth={2} fill="url(#anomalyFill)" /></AreaChart></ResponsiveContainer>
}

function Dashboard({ stats, traffic, anomalies }) {
  return (
    <>
      {/* Hero Editorial Header */}
      <div className="hero-editorial">
        <div className="hero-editorial-left">
          <p className="eyebrow-hero"><span className="live-dot" /> REAL-TIME NETWORK INTELLIGENCE</p>
          <h1 className="hero-headline">Real-Time Autonomous<br />Network Defense</h1>
          <p className="hero-subtext">Perimeter network intelligence powered by live Scapy telemetry & deep inference engines.</p>
        </div>
        <div className="hero-editorial-right">
          <div className="hero-status-pill">
            <span className="hero-status-title">SYSTEM STATUS</span>
            <span className="hero-status-val">PERIMETER PROTECTED</span>
          </div>
        </div>
      </div>

      {/* Floating Telemetry Metric Cards */}
      <div className="stats-grid">
        <StatCard label="Total Packets" value={formatNumber(stats.totalPackets)} detail="+8.2% from previous hour" icon={Database} accent="indigo" />
        <StatCard label="Packets / sec" value="2,184" detail="Current throughput" icon={Gauge} accent="violet" />
        <StatCard label="Active connections" value="1,842" detail="Across 6 monitored nodes" icon={Network} accent="purple" />
        <StatCard label="Normal Packets" value="99.7%" detail="12,421 healthy packets" icon={ShieldCheck} accent="blue" />
        <StatCard label="Anomalies detected" value={stats.anomalies} detail="+4 detected this hour" icon={AlertOctagon} accent="amber" />
        <StatCard label="Current threat level" value="Elevated" detail="2 events require review" icon={Zap} accent="red" />
      </div>

      {/* 3D Hero Scene Section */}
      <section className="panel topology-panel">
        <SectionHeader eyebrow="3D ATMOSPHERIC CORE // NETWORK NODES" title="Network Telemetry Hero Scene" action={<span className="chart-live"><span className="live-dot" /> 6 nodes monitored</span>} />
        <NetworkTopology />
      </section>

      <div className="dashboard-grid">
        <section className="panel traffic-panel">
          <SectionHeader eyebrow="LIVE TELEMETRY" title="Packet activity" action={<span className="chart-live"><span className="live-dot" /> Live stream</span>} />
          <TrafficChart data={traffic} />
        </section>
        <ThreatDistribution />
        <ProtocolDistribution />
      </div>

      <div className="overview-lower">
        <RecentAnomalies anomalies={anomalies} />
        <SecurityEvents />
        <TopSources />
      </div>
    </>
  )
}

function ThreatDistribution() {
  const data = [
    { name: 'Normal', value: 86 },
    { name: 'Low', value: 7 },
    { name: 'Medium', value: 4 },
    { name: 'High', value: 2 },
    { name: 'Critical', value: 1 }
  ]
  return (
    <section className="panel threat-panel">
      <SectionHeader eyebrow="RISK PROFILE" title="Threat distribution" />
      <ResponsiveContainer width="100%" height={205}>
        <BarChart data={data} margin={{ top: 5, right: 0, left: -25, bottom: 0 }}>
          <CartesianGrid stroke="#1e1b4b" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="name" stroke="#64748b" tickLine={false} axisLine={false} fontSize={10} />
          <YAxis stroke="#64748b" tickLine={false} axisLine={false} fontSize={10} />
          <Tooltip content={<ChartTooltip />} />
          <Bar dataKey="value" radius={[3, 3, 0, 0]}>
            {data.map((item) => (
              <Cell key={item.name} fill={{ Normal: '#818cf8', Low: '#a855f7', Medium: '#f59e0b', High: '#ea580c', Critical: '#ef4444' }[item.name]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </section>
  )
}

function ProtocolDistribution() {
  return (
    <section className="panel protocol-panel">
      <SectionHeader eyebrow="TRAFFIC COMPOSITION" title="Protocols" />
      <div className="donut-wrap">
        <ResponsiveContainer width="50%" height={160}>
          <PieChart>
            <Pie data={[{ name: 'TCP', value: 68 }, { name: 'UDP', value: 24 }, { name: 'Other', value: 8 }]} innerRadius={47} outerRadius={69} paddingAngle={4} dataKey="value" stroke="none">
              {['#818cf8', '#c084fc', '#334155'].map((color) => <Cell key={color} fill={color} />)}
            </Pie>
            <text x="25%" y="50%" textAnchor="middle" dominantBaseline="middle" fill="#f8fafc" fontSize="20" fontWeight="700">68%</text>
          </PieChart>
        </ResponsiveContainer>
        <div className="legend-list">
          <div><i className="legend-dot violet" />TCP <b>68%</b></div>
          <div><i className="legend-dot purple" />UDP <b>24%</b></div>
          <div><i className="legend-dot slate" />Other <b>8%</b></div>
        </div>
      </div>
    </section>
  )
}

function RecentAnomalies({ anomalies }) {
  return (
    <section className="panel anomalies-panel">
      <SectionHeader eyebrow="DETECTION FEED" title="Recent anomalies" action={<a className="text-link" href="#/anomalies">View all <ChevronRight size={13} /></a>} />
      <AnomalyTable anomalies={anomalies.slice(0, 4)} compact />
    </section>
  )
}

function AnomalyTable({ anomalies, compact = false, onSelect }) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
            <th>Anomaly type</th>
            <th>Score</th>
            <th>Severity</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {anomalies.map((item) => (
            <tr key={item.id} onClick={() => onSelect?.(item)} className={onSelect ? 'clickable-row' : ''}>
              <td className="muted">{item.time}</td>
              <td className="mono">{item.source}</td>
              <td className="mono">{item.destination}</td>
              <td><span className="protocol-tag">{item.protocol}</span></td>
              <td>{item.type}</td>
              <td><span className={`score ${item.score > 80 ? 'score-high' : ''}`}>{item.score}%</span></td>
              <td><span className={severityClass(item.severity)}>{item.severity}</span></td>
              <td><span className="status-text">{item.status}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
      {!anomalies.length && <div className="empty-state">No anomalies match the selected filters.</div>}
    </div>
  )
}

function LiveAlert({ anomaly }) {
  return (
    <section className="alert-panel">
      <div className="alert-heading">
        <div className="alert-pulse"><AlertOctagon size={22} /></div>
        <div><p className="eyebrow">LIVE ALERT / 00:03 AGO</p><h2>Anomaly detected</h2></div>
        <span className={severityClass(anomaly.severity)}>{anomaly.severity}</span>
      </div>
      <div className="alert-grid">
        <div><span>Source</span><strong>{anomaly.source}</strong></div>
        <div><span>Type</span><strong>{anomaly.type}</strong></div>
        <div><span>Anomaly score</span><strong className="threat-value">{anomaly.score}%</strong></div>
        <div><span>Destination</span><strong>{anomaly.destination}</strong></div>
      </div>
      <a href="#/anomalies" className="alert-action">Open investigation <ChevronRight size={15} /></a>
    </section>
  )
}

function SecurityEvents() {
  return (
    <section className="panel security-events">
      <SectionHeader eyebrow="SECURITY EVENTS" title="Recent activity" />
      <div className="event-row"><span className="event-mark red"><AlertOctagon size={13} /></span><div><strong>Model flagged deviation</strong><small>10.171.100.58 · Traffic spike</small></div><time>2m ago</time></div>
      <div className="event-row"><span className="event-mark amber"><FileWarning size={13} /></span><div><strong>Investigation required</strong><small>10.10.4.8 · DNS request rate</small></div><time>4m ago</time></div>
      <div className="event-row"><span className="event-mark green"><ShieldCheck size={13} /></span><div><strong>Sensor health check passed</strong><small>All capture interfaces responding</small></div><time>6m ago</time></div>
    </section>
  )
}

function TopSources() {
  const sources = [['10.171.100.58', '4,281', '94%'], ['192.168.1.15', '2,108', '18%'], ['10.10.4.8', '1,844', '62%'], ['172.16.0.22', '1,222', '81%']]
  const destinations = [['40.79.150.124', '4,912'], ['10.0.0.18', '2,844'], ['10.0.0.4', '1,284'], ['10.0.0.22', '1,028']]
  return (
    <section className="panel top-sources">
      <SectionHeader eyebrow="TRAFFIC CONTEXT" title="Top endpoints" />
      <p className="list-label">SOURCE IPs</p>
      <div className="ip-list">{sources.map(([ip, packets, score], index) => <div key={ip}><span className="rank">{index + 1}</span><span className="mono">{ip}</span><b>{packets}</b><em className={score === '94%' || score === '81%' ? 'text-red' : ''}>{score}</em></div>)}</div>
      <p className="list-label destination-label">DESTINATION IPs</p>
      <div className="ip-list">{destinations.map(([ip, packets]) => <div key={ip}><span className="rank">-</span><span className="mono">{ip}</span><b>{packets}</b></div>)}</div>
    </section>
  )
}

function Monitoring({ traffic, packets, stats }) {
  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">REAL-TIME SENSOR VIEW</p>
          <h2>Live monitoring</h2>
          <p>Streaming packet telemetry across the monitored network perimeter.</p>
        </div>
        <div className="monitoring-active"><span className="live-dot" /> Monitoring active</div>
      </div>
      <div className="metric-strip">
        <div><span>Packets / sec</span><strong>{traffic.at(-1)?.packets || 0}</strong><small>+12.4% <em>vs baseline</em></small></div>
        <div><span>Bytes / sec</span><strong>2.84 MB</strong><small>+4.8% <em>vs baseline</em></small></div>
        <div><span>Active connections</span><strong>1,842</strong><small className="good">Stable <em>last 5 min</em></small></div>
        <div><span>Normal / anomaly</span><strong>{formatNumber(stats.normalTraffic)} <i>/</i> {stats.anomalies}</strong><small className="good">99.7% healthy</small></div>
      </div>
      <section className="panel topology-panel monitoring-topology">
        <SectionHeader eyebrow="NETWORK HERO SCENE // SENSORS" title="Live network map" action={<span className="chart-live"><span className="live-dot" /> Streaming</span>} />
        <NetworkTopology />
      </section>
      <div className="dashboard-grid monitoring-grid">
        <section className="panel traffic-panel">
          <SectionHeader eyebrow="PACKETS PER SECOND" title="Live traffic stream" />
          <TrafficChart data={traffic} />
        </section>
        <LiveConnectionHealth />
      </div>
      <section className="panel flow-panel">
        <SectionHeader eyebrow="STREAMING DATA" title="Live packet flow" action={<span className="stream-status"><span className="live-dot" /> Receiving packets</span>} />
        <PacketTable packets={packets} />
      </section>
    </>
  )
}

function LiveConnectionHealth() {
  return (
    <section className="panel health-panel">
      <SectionHeader eyebrow="SENSOR HEALTH" title="Connection health" />
      <div className="health-ring"><div><strong>98.6</strong><span>HEALTH SCORE</span></div></div>
      <div className="health-list">
        <div><span className="live-dot" />Packet ingestion <b>Normal</b></div>
        <div><span className="live-dot" />Model inference <b>12ms</b></div>
        <div><span className="live-dot" />API gateway <b>42ms</b></div>
      </div>
    </section>
  )
}

function Anomalies({ anomalies, onSelect }) {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('All severities')
  const [protocol, setProtocol] = useState('All protocols')
  const [type, setType] = useState('All types')
  const filtered = useMemo(() => anomalies.filter((item) => (item.source.includes(query) || item.destination.includes(query) || item.type.toLowerCase().includes(query.toLowerCase())) && (severity === 'All severities' || item.severity === severity) && (protocol === 'All protocols' || item.protocol === protocol) && (type === 'All types' || item.type === type)), [anomalies, query, severity, protocol, type])

  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">THREAT INTELLIGENCE</p>
          <h2>Anomaly detection</h2>
          <p>Investigate model-flagged deviations from learned network behavior.</p>
        </div>
        <div className="heading-count"><strong>{anomalies.length + 32}</strong><span>Total detections</span></div>
      </div>
      <div className="severity-summary">
        <div><span>Total detections</span><b>{anomalies.length + 32}</b></div>
        <div className="critical"><span>Critical</span><b>5</b></div>
        <div className="high"><span>High</span><b>11</b></div>
        <div className="medium"><span>Medium</span><b>14</b></div>
        <div className="low"><span>Low</span><b>7</b></div>
      </div>
      <section className="panel full-panel">
        <div className="filter-bar">
          <div className="search-box">
            <Search size={16} />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search IP or anomaly type" />
          </div>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}><option>All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>
          <select value={protocol} onChange={(e) => setProtocol(e.target.value)}><option>All protocols</option><option>TCP</option><option>UDP</option></select>
          <select value={type} onChange={(e) => setType(e.target.value)}><option>All types</option>{[...new Set(anomalies.map((item) => item.type))].map((item) => <option key={item}>{item}</option>)}</select>
          <SlidersHorizontal size={18} className="filter-icon" />
        </div>
        <AnomalyTable anomalies={filtered} onSelect={onSelect} />
      </section>
    </>
  )
}

function Analytics({ analytics, stats }) {
  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">SECURITY INTELLIGENCE</p>
          <h2>Analytics overview</h2>
          <p>Historical context for traffic health and model detections.</p>
        </div>
        <div className="date-chip">Last 60 minutes <ChevronRight size={14} /></div>
      </div>
      <div className="analytics-kpis">
        <div><span>Total packets</span><strong>{formatNumber(stats.totalPackets)}</strong></div>
        <div><span>Anomaly percentage</span><strong>0.30%</strong></div>
        <div><span>Mean detection score</span><strong>71.4%</strong></div>
        <div><span>Peak throughput</span><strong>612 <small>pkt/s</small></strong></div>
      </div>
      <div className="analytics-grid">
        <section className="panel large-chart">
          <SectionHeader eyebrow="TRAFFIC VOLUME" title="Traffic over time" />
          <TrafficChart data={analytics.traffic} />
        </section>
        <ProtocolDistribution />
        <section className="panel large-chart">
          <SectionHeader eyebrow="DETECTION COUNTS" title="Anomalies over time" />
          <ResponsiveContainer width="100%" height={245}>
            <LineChart data={analytics.traffic} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
              <CartesianGrid stroke="#1e1b4b" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="time" stroke="#64748b" tickLine={false} axisLine={false} fontSize={10} />
              <YAxis stroke="#64748b" tickLine={false} axisLine={false} fontSize={10} />
              <Tooltip content={<ChartTooltip />} />
              <Line type="monotone" dataKey="anomaly" name="Anomalies" stroke="#ef4444" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </section>
        <ThreatDistribution />
        <AnalyticsDistribution />
      </div>
    </>
  )
}

function AnalyticsDistribution() {
  const sizes = [{ name: '0-256', value: 18 }, { name: '257-512', value: 31 }, { name: '513-1024', value: 27 }, { name: '1025+', value: 24 }]
  const sources = [{ name: '10.171.100.58', value: 4281 }, { name: '192.168.1.15', value: 2108 }, { name: '10.10.4.8', value: 1844 }, { name: '172.16.0.22', value: 1222 }]
  return (
    <>
      <section className="panel analytics-mini">
        <SectionHeader eyebrow="PACKET PROFILE" title="Packet-size distribution" />
        <ResponsiveContainer width="100%" height={185}>
          <BarChart data={sizes}>
            <CartesianGrid stroke="#1e1b4b" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="name" stroke="#64748b" tickLine={false} axisLine={false} fontSize={9} />
            <YAxis stroke="#64748b" tickLine={false} axisLine={false} fontSize={9} />
            <Bar dataKey="value" fill="#818cf8" radius={[2, 2, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </section>
      <section className="panel analytics-mini">
        <SectionHeader eyebrow="TRAFFIC ORIGINS" title="Top source IPs" />
        <ResponsiveContainer width="100%" height={185}>
          <BarChart data={sources} layout="vertical" margin={{ left: 20, right: 10 }}>
            <CartesianGrid stroke="#1e1b4b" strokeDasharray="3 3" horizontal={false} />
            <XAxis type="number" hide />
            <YAxis type="category" dataKey="name" stroke="#64748b" tickLine={false} axisLine={false} fontSize={8} width={78} />
            <Bar dataKey="value" fill="#c084fc" radius={[0, 2, 2, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </section>
    </>
  )
}

function TrafficTable({ packets }) {
  const [query, setQuery] = useState('')
  const [protocol, setProtocol] = useState('All protocols')
  const [status, setStatus] = useState('All statuses')
  const [page, setPage] = useState(1)
  const filtered = packets.filter((packet) => (packet.src_ip.includes(query) || packet.dst_ip.includes(query)) && (protocol === 'All protocols' || packet.protocol === protocol) && (status === 'All statuses' || packet.status === status))

  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">PACKET INSPECTION</p>
          <h2>Network traffic</h2>
          <p>Normalized packet metadata from the Scapy sensor pipeline.</p>
        </div>
        <div className="capture-state"><span className="live-dot" /> Capture stream active</div>
      </div>
      <section className="panel full-panel">
        <div className="table-toolbar">
          <div><strong>Latest packet events</strong><span>Schema-compatible with <code>traffic.json</code></span></div>
          <button className="secondary-button"><Table2 size={15} /> Export view</button>
        </div>
        <div className="filter-bar traffic-filters">
          <div className="search-box">
            <Search size={16} />
            <input value={query} onChange={(event) => { setQuery(event.target.value); setPage(1) }} placeholder="Search source or destination IP" />
          </div>
          <select value={protocol} onChange={(event) => setProtocol(event.target.value)}><option>All protocols</option><option>TCP</option><option>UDP</option></select>
          <select value={status} onChange={(event) => setStatus(event.target.value)}><option>All statuses</option><option>Normal</option><option>Warning</option><option>Anomaly</option></select>
          <span className="filter-date">Last 15 minutes</span>
        </div>
        <PacketTable packets={filtered} />
        <div className="pagination">
          <span>Showing {filtered.length} of 12,458 packets</span>
          <div><button disabled={page === 1} onClick={() => setPage(1)}>Previous</button><b>{page}</b><button onClick={() => setPage(page + 1)}>Next</button></div>
        </div>
      </section>
    </>
  )
}

function PacketTable({ packets }) {
  return (
    <div className="table-scroll">
      <table className="packet-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
            <th>Source port</th>
            <th>Destination port</th>
            <th>Packet size</th>
            <th>Status</th>
            <th>Anomaly score</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((packet) => (
            <tr key={`${packet.timestamp}-${packet.src_ip}`}>
              <td className="muted mono">{packet.timestamp}</td>
              <td className="mono">{packet.src_ip}</td>
              <td className="mono">{packet.dst_ip}</td>
              <td><span className="protocol-tag">{packet.protocol}</span></td>
              <td className="mono">{packet.src_port}</td>
              <td className="mono">{packet.dst_port}</td>
              <td>{formatNumber(packet.packet_size)} B</td>
              <td><span className={`packet-status ${packet.status?.toLowerCase()}`}>{packet.status || 'Normal'}</span></td>
              <td><span className={packet.score > 60 ? 'score score-high' : 'score'}>{packet.score || 0}%</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SettingsPage() {
  return (
    <div className="page-heading">
      <div>
        <p className="eyebrow">SYSTEM CONFIGURATION</p>
        <h2>Settings</h2>
        <p>Sensor and detection settings will be connected to the backend control plane.</p>
      </div>
      <section className="panel placeholder-panel">
        <Settings size={24} />
        <strong>Configuration controls are staged</strong>
        <span>Backend integration will expose live sensor configuration here.</span>
      </section>
    </div>
  )
}

function AnomalyModal({ anomaly, onClose }) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div><p className="eyebrow">DETECTION DETAIL / #{String(anomaly.id).padStart(4, '0')}</p><h2>{anomaly.type}</h2></div>
          <button className="icon-button" onClick={onClose}><X size={18} /></button>
        </div>
        <div className="modal-severity">
          <span className={severityClass(anomaly.severity)}>{anomaly.severity}</span>
          <span className="score score-high">{anomaly.score}% anomaly score</span>
          <span className="status-text">{anomaly.status}</span>
        </div>
        <div className="detail-grid">
          {[['Source IP', anomaly.source], ['Destination IP', anomaly.destination], ['Protocol', anomaly.protocol], ['Source port', anomaly.srcPort], ['Destination port', anomaly.dstPort], ['Packet size', `${anomaly.packetSize} bytes`], ['Timestamp', anomaly.timestamp], ['Detection reason', anomaly.reason]].map(([label, value]) => (
            <div key={label}><span>{label}</span><strong className={label.includes('IP') || label.includes('port') ? 'mono' : ''}>{value}</strong></div>
          ))}
        </div>
        <button className="secondary-button modal-close" onClick={onClose}>Close investigation</button>
      </div>
    </div>
  )
}

export default App
