export interface CVESummary {
 cve_id: string;
 description: string;
 cvss_score: number;
 severity: string;
 affected_assets_count: number;
 published_date: string;
}

export interface SeverityDistribution {
 critical: number;
 high: number;
 medium: number;
 low: number;
}

export interface IntelSummary {
 total_cves: number;
 critical_cves: number;
 severity_distribution: SeverityDistribution;
 top_cves: CVESummary[];
}

export const intelApi = {
 getSummary: async (): Promise<IntelSummary> => {
 const res = await apiClient.get<IntelSummary>('/intel/cve-summary');
 return res.data;
 },

 getSeverityDistribution: async (): Promise<SeverityDistribution> => {
 const res = await apiClient.get<SeverityDistribution>('/intel/severity-distribution');
 return res.data;
 },
};
