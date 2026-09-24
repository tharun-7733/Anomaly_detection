import { anomalies, initialTraffic, packets, protocolData, severityData, stats } from '../data/mockData'

const pause = (data) => Promise.resolve(data)

export const getDashboardStats = () => pause({ ...stats })
export const getTraffic = () => pause([...initialTraffic])
export const getAnomalies = () => pause([...anomalies])
export const getPackets = () => pause([...packets])
export const getAnalytics = () => pause({ traffic: initialTraffic, anomalies, protocolData, severityData })
export const getNetworkStats = getDashboardStats
export const getLivePackets = getPackets
export const getNetworkTopology = () => pause({ nodes: [], links: [] })
