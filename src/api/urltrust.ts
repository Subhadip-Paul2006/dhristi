export interface URLTrustResult {
 url: string;
 trust_score: number;
 risk_level: 'safe' | 'low_risk' | 'medium_risk' | 'high_risk' | 'malicious';
 categories: string[];
 threat_indicators: string[];
 last_scanned: string;
 recommendation: string;
}

export const urltrustApi = {
 analyze: async (url: string): Promise<URLTrustResult> => {
 const res = await apiClient.post<URLTrustResult>('/urltrust/analyze', { url });
 return res.data;
 },

 bulkAnalyze: async (urls: string[]): Promise<URLTrustResult[]> => {
 const res = await apiClient.post<URLTrustResult[]>('/urltrust/bulk-analyze', { urls });
 return res.data;
 },
};
