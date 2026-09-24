const API_URL = "/api";

const fetchData = async (endpoint) => {
    try {
        const response = await fetch(`${API_URL}${endpoint}`);
        if (!response.ok) throw new Error("Network response was not ok");
        return await response.json();
    } catch (error) {
        console.error(`Error fetching ${endpoint}:`, error);
        return null;
    }
};

export const getDashboardStats = async () => {
    const data = await fetchData("/stats");
    return data || { totalPackets: 0, normalTraffic: 0, anomalies: 0 };
};

export const getTraffic = async () => {
    const data = await fetchData("/traffic");
    return data || [];
};

export const getAnomalies = async () => {
    const data = await fetchData("/anomalies");
    // Format anomalies to match what the frontend expects
    return (data || []).map(a => ({
        id: a.id,
        time: a.timestamp,
        source: a.src_ip,
        destination: a.dst_ip,
        protocol: a.protocol,
        type: a.type,
        score: a.score,
        severity: a.severity,
        status: a.status,
        srcPort: a.src_port,
        dstPort: a.dst_port,
        packetSize: a.packet_size
    }));
};

export const getPackets = async () => {
    const data = await fetchData("/packets?limit=20");
    return data || [];
};

export const getAnalytics = async () => {
    const data = await fetchData("/analytics");
    return data || { traffic: [], anomalies: [] };
};

export const getNetworkStats = getDashboardStats;
export const getLivePackets = getPackets;
export const getNetworkTopology = () => Promise.resolve({ nodes: [], links: [] });
