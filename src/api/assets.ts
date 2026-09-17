export interface Asset {
 id: string;
 ip_address: string;
 hostname: string;
 zone: string;
 asset_type: string;
 risk_score: number;
 is_crown_jewel: boolean;
 criticality?: string;
 services: Service[];
 findings: Finding[];
 created_at?: string;
 updated_at?: string;
}

export interface Service {
 id: string;
 asset_id: string;
 name: string;
 port: number;
 protocol: string;
 version?: string;
}

export interface Finding {
 id: string;
 asset_id: string;
 title: string;
 description: string;
 severity: 'low' | 'medium' | 'high' | 'critical';
 cve_id?: string;
 status: 'open' | 'in_progress' | 'resolved' | 'risk_accepted';
 cvss_score?: number;
 created_at?: string;
}

export interface UpdateFindingRequest {
 status?: string;
 severity?: string;
}

export const assetsApi = {
 list: async (): Promise<Asset[]> => {
 const res = await apiClient.get<Asset[]>('/assets');
 return res.data;
 },

 get: async (id: string): Promise<Asset> => {
 const res = await apiClient.get<Asset>(`/assets/${id}`);
 return res.data;
 },

 updateFinding: async (assetId: string, findingId: string, data: UpdateFindingRequest): Promise<Finding> => {
 const res = await apiClient.patch<Finding>(`/assets/${assetId}/findings/${findingId}`, data);
 return res.data;
 },
};
