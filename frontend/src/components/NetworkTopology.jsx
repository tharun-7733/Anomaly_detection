import { useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Grid, Html, Line, OrbitControls } from '@react-three/drei'
import * as THREE from 'three'
import { Pause, Play, RefreshCcw, Rotate3d, ZoomIn } from 'lucide-react'

const topologyNodes = [
  { id: 'gateway', label: 'GATEWAY', ip: '10.171.100.1', position: [0, 0, 0], role: 'Core router', status: 'Normal', protocol: 'TCP', packets: '8,412', connections: 18, packetRate: 2184, lastDetected: '2 sec ago' },
  { id: 'device', label: 'LOCAL DEVICE', ip: '10.171.100.58', position: [-2.7, 1.25, 0.25], role: 'Endpoint', status: 'Anomaly', protocol: 'TCP', severity: 'High', score: 94, packets: '4,281', connections: 12, packetRate: 386, lastDetected: '14:32:08' },
  { id: 'dns', label: 'DNS', ip: '10.0.0.4', position: [-2.35, -1.35, -0.3], role: 'Resolver', status: 'Normal', protocol: 'UDP', packets: '1,284', connections: 6, packetRate: 142, lastDetected: '12 sec ago' },
  { id: 'web', label: 'WEB SERVER', ip: '40.79.150.124', position: [2.5, 1.35, 0.15], role: 'External server', status: 'Normal', protocol: 'TCP', packets: '2,914', connections: 9, packetRate: 524, lastDetected: '4 sec ago' },
  { id: 'api', label: 'API SERVER', ip: '10.0.0.18', position: [2.65, -1.05, 0.4], role: 'Application node', status: 'Warning', protocol: 'TCP', packets: '1,920', connections: 8, packetRate: 294, lastDetected: '8 sec ago' },
  { id: 'database', label: 'DATABASE', ip: '10.0.0.22', position: [0.15, -2.35, -0.2], role: 'Internal service', status: 'Normal', protocol: 'TCP', packets: '1,028', connections: 5, packetRate: 118, lastDetected: '6 sec ago' },
]

const links = [
  ['device', 'gateway', 'anomaly'], ['dns', 'gateway', 'normal'], ['gateway', 'web', 'normal'],
  ['gateway', 'api', 'normal'], ['gateway', 'database', 'normal'], ['device', 'web', 'anomaly'],
]

function stateColor(status) {
  return status === 'Anomaly' ? '#ef4444' : status === 'Warning' ? '#f59e0b' : '#818cf8'
}

function getLinkCurve(pos1, pos2) {
  const v1 = new THREE.Vector3(...pos1)
  const v2 = new THREE.Vector3(...pos2)
  const dist = v1.distanceTo(v2)
  const mid = new THREE.Vector3().addVectors(v1, v2).multiplyScalar(0.5)
  mid.y += Math.max(0.38, dist * 0.15)
  return new THREE.QuadraticBezierCurve3(v1, mid, v2)
}

function Node({ node, selected, onSelect }) {
  const coreRef = useRef()
  const shellRef = useRef()
  const pulseRef = useRef()
  const color = stateColor(node.status)
  const isGateway = node.id === 'gateway'
  const isAnomaly = node.status === 'Anomaly'

  useFrame(({ clock }) => {
    const time = clock.elapsedTime
    if (shellRef.current) {
      shellRef.current.rotation.y = time * 0.35
      shellRef.current.rotation.x = time * 0.18
    }
    if (pulseRef.current && isAnomaly) {
      const scale = 1 + (Math.sin(time * 3.5) * 0.18 + 0.18)
      pulseRef.current.scale.setScalar(scale)
    }
  })

  const [x, y, z] = node.position
  const groundY = -2.5

  return (
    <group position={node.position}>
      {/* Vertical spatial elevation drop-stem */}
      <Line
        points={[[0, 0, 0], [0, groundY - y, 0]]}
        color={isAnomaly ? '#ef4444' : '#6366f1'}
        lineWidth={0.8}
        transparent
        opacity={0.35}
      />
      {/* Ground target ring */}
      <mesh position={[0, groundY - y, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[0.08, 0.14, 16]} />
        <meshBasicMaterial color={color} transparent opacity={0.3} side={THREE.DoubleSide} />
      </mesh>

      {/* Main Node Click Area */}
      <group onClick={(event) => { event.stopPropagation(); onSelect(node) }}>
        {/* Anomaly pulsing outer aura */}
        {isAnomaly && (
          <mesh ref={pulseRef}>
            <sphereGeometry args={[0.32, 24, 24]} />
            <meshBasicMaterial color="#ef4444" transparent opacity={0.25} />
          </mesh>
        )}

        {/* Outer Rotating Wireframe */}
        <mesh ref={shellRef}>
          {isGateway ? (
            <octahedronGeometry args={[0.3, 0]} />
          ) : (
            <icosahedronGeometry args={[0.22, 0]} />
          )}
          <meshStandardMaterial
            color={isGateway ? '#ffffff' : color}
            wireframe
            transparent
            opacity={selected ? 0.95 : 0.55}
            emissive={color}
            emissiveIntensity={0.4}
          />
        </mesh>

        {/* Inner Core */}
        <mesh ref={coreRef}>
          <sphereGeometry args={[isGateway ? 0.15 : 0.1, 24, 24]} />
          <meshStandardMaterial
            color={isGateway ? '#ffffff' : color}
            emissive={color}
            emissiveIntensity={isAnomaly ? 2.0 : 0.6}
            roughness={0.2}
            metalness={0.8}
          />
        </mesh>

        {/* Localized node light */}
        <pointLight
          color={color}
          intensity={isAnomaly ? 5 : isGateway ? 4 : 2}
          distance={4}
        />

        {/* Selection Ring */}
        {selected && (
          <mesh rotation={[-Math.PI / 2, 0, 0]}>
            <ringGeometry args={[0.34, 0.38, 32]} />
            <meshBasicMaterial color="#818cf8" transparent opacity={0.9} side={THREE.DoubleSide} />
          </mesh>
        )}

        {/* Tactical HUD Label */}
        <Html distanceFactor={8.5} position={[0, 0.34, 0]} center pointerEvents="none">
          <div className={`node-label node-${node.status.toLowerCase()} ${selected ? 'node-selected' : ''}`}>
            <div className="node-label-inner">
              <span className={`node-dot dot-${node.status.toLowerCase()}`} />
              <strong>{node.label}</strong>
              <span className="node-ip">{node.ip}</span>
            </div>
          </div>
        </Html>
      </group>
    </group>
  )
}

function Packet({ curve, color, offset, paused }) {
  const ref = useRef()
  useFrame(({ clock }) => {
    if (!curve) return
    const progress = ((paused ? 0.42 : clock.elapsedTime * 0.16) + offset) % 1
    const point = curve.getPoint(progress)
    if (ref.current) {
      ref.current.position.copy(point)
    }
  })
  return (
    <mesh ref={ref}>
      <sphereGeometry args={[0.045, 16, 16]} />
      <meshBasicMaterial color={color} />
    </mesh>
  )
}

function ConnectionLink({ fromNode, toNode, type, paused, offset }) {
  const curve = useMemo(() => {
    if (!fromNode || !toNode) return null
    return getLinkCurve(fromNode.position, toNode.position)
  }, [fromNode, toNode])

  const points = useMemo(() => {
    if (!curve) return []
    return curve.getPoints(36)
  }, [curve])

  if (!curve) return null

  const isAnomaly = type === 'anomaly'
  const lineColor = isAnomaly ? '#ef4444' : '#4338ca'
  const packetColor = isAnomaly ? '#f87171' : '#c084fc'

  return (
    <group>
      <Line
        points={points}
        color={lineColor}
        lineWidth={isAnomaly ? 2.5 : 1.2}
        transparent
        opacity={isAnomaly ? 0.85 : 0.5}
      />
      <Packet curve={curve} color={packetColor} offset={offset} paused={paused} />
    </group>
  )
}

function Scene({ selectedNode, onSelect, paused }) {
  const nodes = useMemo(() => Object.fromEntries(topologyNodes.map((node) => [node.id, node])), [])

  return (
    <>
      <color attach="background" args={['#03040a']} />
      <fog attach="fog" args={['#03040a', 5, 18]} />

      <ambientLight intensity={0.4} color="#1e1b4b" />
      <directionalLight position={[6, 12, 6]} intensity={2.6} color="#818cf8" />
      <pointLight position={[0, 4, 2]} intensity={6} color="#6366f1" distance={10} />
      <pointLight position={[-4, -1, 1]} intensity={5} color="#ef4444" distance={8} />

      {/* 3D Spatial Grid */}
      <Grid
        args={[12, 12]}
        cellSize={0.6}
        cellThickness={0.8}
        cellColor="#1e1b4b"
        sectionSize={3}
        sectionThickness={1.4}
        sectionColor="#312e81"
        fadeDistance={10}
        fadeStrength={1.8}
        position={[0, -2.5, 0]}
      />

      {/* 3D Curved Connection Paths */}
      {links.map(([from, to, type], index) => (
        <ConnectionLink
          key={`${from}-${to}`}
          fromNode={nodes[from]}
          toNode={nodes[to]}
          type={type}
          paused={paused}
          offset={index * 0.18}
        />
      ))}

      {/* 3D Physical Nodes */}
      {topologyNodes.map((node) => (
        <Node
          key={node.id}
          node={node}
          selected={selectedNode?.id === node.id}
          onSelect={onSelect}
        />
      ))}
    </>
  )
}

export default function NetworkTopology() {
  const [selectedNode, setSelectedNode] = useState(topologyNodes[1])
  const [paused, setPaused] = useState(false)
  const [resetView, setResetView] = useState(0)
  const controls = useRef()

  const resetCamera = () => {
    controls.current?.reset()
    setResetView((value) => value + 1)
  }

  return (
    <div className="topology-wrap">
      <Canvas
        key={resetView}
        camera={{ position: [0, 1.8, 6.8], fov: 38 }}
        dpr={[1, 2]}
        gl={{ antialias: true }}
        onPointerMissed={() => setSelectedNode(null)}
      >
        <Scene selectedNode={selectedNode} onSelect={setSelectedNode} paused={paused} />
        <OrbitControls
          ref={controls}
          enablePan
          enableZoom
          enableRotate
          minDistance={3.8}
          maxDistance={10}
          autoRotate={false}
          maxPolarAngle={Math.PI / 2 + 0.05}
        />
      </Canvas>

      <div className="topology-toolbar">
        <span><i className="legend-dot green" /> Healthy Node</span>
        <span><i className="legend-dot amber" /> Warning State</span>
        <span><i className="legend-dot red" /> Threat Event</span>
        <small>3D Network Topology · Drag to Orbit · Scroll to Zoom</small>
      </div>

      <div className="topology-controls">
        <button onClick={() => setPaused((value) => !value)} title={paused ? 'Resume traffic' : 'Pause traffic'}>
          {paused ? <Play size={13} /> : <Pause size={13} />} {paused ? 'Resume' : 'Pause'}
        </button>
        <button onClick={resetCamera} title="Reset camera">
          <RefreshCcw size={13} /> Reset View
        </button>
        <span><Rotate3d size={13} /> Orbit</span>
        <span><ZoomIn size={13} /> Zoom</span>
      </div>

      {selectedNode && (
        <div className="node-details">
          <div className="node-details-header">
            <div>
              <p className="eyebrow">NODE TELEMETRY</p>
              <strong>{selectedNode.label}</strong>
            </div>
            <button onClick={() => setSelectedNode(null)} aria-label="Close detail panel">×</button>
          </div>
          <div className="node-detail-ip">{selectedNode.ip}</div>
          <div className="node-detail-grid">
            <span>Status <b className={selectedNode.status === 'Normal' ? 'text-green' : selectedNode.status === 'Warning' ? 'text-amber' : 'text-red'}>{selectedNode.status === 'Anomaly' ? 'THREAT DETECTED' : selectedNode.status}</b></span>
            <span>Protocol <b>{selectedNode.protocol}</b></span>
            <span>Packets <b>{selectedNode.packets}</b></span>
            <span>Connections <b>{selectedNode.connections}</b></span>
            <span>Packet Rate <b>{selectedNode.packetRate} / sec</b></span>
            <span>Last Activity <b>{selectedNode.lastDetected}</b></span>
          </div>
          {selectedNode.score && (
            <div className="node-score">
              <span>Anomaly Threat Score</span>
              <strong>{selectedNode.score}%</strong>
              <i><em style={{ width: `${selectedNode.score}%` }} /></i>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
