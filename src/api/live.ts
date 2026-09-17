export interface DeviceInfo {
 id: string;
 ip_address: string;
 hostname: string;
 zone: string;
 asset_type: string;
 risk_score: number;
 last_seen: string;
 is_online: boolean;
}

export interface ThreatEvent {
 id: string;
 title: string;
 description: string;
 severity: 'low' | 'medium' | 'high' | 'critical';
 asset_id?: string;
 source_ip?: string;
 detected_at: string;
 status: string;
}

export interface DeviceBatch {
 total_devices: number;
 online_devices: number;
 zones: Record<string, number>;
}

export interface CoverageStatus {
 total_assets: number;
 monitored_assets: number;
 coverage_percentage: number;
 gaps: string[];
}

export const liveApi = {
 getDeviceBatch: async (): Promise<DeviceBatch> => {
 const res = await apiClient.get<DeviceBatch>('/live/devices/batch');
 return res.data;
 },

 getDevices: async (): Promise<DeviceInfo[]> => {
 const res = await apiClient.get<DeviceInfo[]>('/live/devices');
 return res.data;
 },

 getThreats: async (): Promise<ThreatEvent[]> => {
 const res = await apiClient.get<ThreatEvent[]>('/live/threats');
 return res.data;
 },

 getCoverage: async (): Promise<CoverageStatus> => {
 const res = await apiClient.get<CoverageStatus>('/live/coverage');
 return res.data;
 },
};
