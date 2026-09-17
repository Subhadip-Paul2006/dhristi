export interface AIRemediation {
 finding_id: string;
 suggested_fix: string;
 priority: 'immediate' | 'short_term' | 'long_term';
 estimated_effort: string;
 references: string[];
}

export interface AIImpactEstimate {
 financial_impact_usd: number;
 business_impact: string;
 affected_services: string[];
 data_exposure_estimate: string;
 recovery_time_estimate: string;
 confidence_score: number;
}

export interface AIPrediction {
 asset_id: string;
 predicted_risk_score: number;
 risk_change_probability: number;
 suggested_actions: string[];
 time_horizon_days: number;
}

export const aiApi = {
 getRemediation: async (findingId: string): Promise<AIRemediation> => {
 const res = await apiClient.post<AIRemediation>(`/ai/remediate/${findingId}`);
 return res.data;
 },

 estimateImpact: async (pathId: string): Promise<AIImpactEstimate> => {
 const res = await apiClient.post<AIImpactEstimate>(`/ai/estimate-impact/${pathId}`);
 return res.data;
 },

 getPredictions: async (): Promise<AIPrediction[]> => {
 const res = await apiClient.get<AIPrediction[]>('/ai/predictions');
 return res.data;
 },
};
