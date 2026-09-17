export interface GraphNode {
 id: string;
 label: string;
 type: 'asset' | 'internet' | 'dmz' | 'internal' | 'cloud' | 'critical';
 zone: string;
 ip?: string;
 risk_score?: number;
}

export interface GraphEdge {
 id: string;
 source: string;
 target: string;
 label?: string;
 attack_vector?: string;
}

export interface GraphData {
 nodes: GraphNode[];
 edges: GraphEdge[];
 zones: string[];
 live_devices: number;
 network_threats: number;
}

export const graphApi = {
 getGraph: async (): Promise<GraphData> => {
 const res = await apiClient.get<GraphData>('/graph');
 return res.data;
 },
};
