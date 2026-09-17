export interface AttackPath {
 id: string;
 name: string;
 source_asset_id: string;
 target_asset_id: string;
 path: string[];
 risk_score: number;
 estimated_exposure_usd: number;
 ai_explanation?: string;
 ai_impact_estimate?: AIImpactEstimate;
 created_at?: string;
}

export interface AIImpactEstimate {
 financial_impact_usd: number;
 business_impact: string;
 affected_services: string[];
 data_exposure_estimate: string;
 recovery_time_estimate: string;
 confidence_score: number;
}

export const pathsApi = {
 list: async (): Promise<AttackPath[]> => {
 const res = await apiClient.get<AttackPath[]>('/paths');
 return res.data;
 },

 get: async (id: string): Promise<AttackPath> => {
 const res = await apiClient.get<AttackPath>(`/paths/${id}`);
 return res.data;
 },

 estimateImpact: async (pathId: string): Promise<AIImpactEstimate> => {
 const res = await apiClient.post<AIImpactEstimate>(`/paths/${pathId}/estimate-impact`);
 return res.data;
 },
};
