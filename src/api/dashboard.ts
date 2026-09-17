export interface DashboardSummary {
 total_exposure_usd: number;
 open_findings: number;
 critical_assets: number;
 top_attack_path: AttackPathSummary;
 severity_distribution: {
 low: number;
 medium: number;
 high: number;
 critical: number;
 };
 zone_summary: ZoneSummary[];
}

export interface AttackPathSummary {
 id: string;
 name: string;
 risk_score: number;
 estimated_exposure_usd: number;
 target_asset: string;
}

export interface ZoneSummary {
 zone: string;
 asset_count: number;
 avg_risk_score: number;
 open_findings: number;
 critical_findings: number;
}

export const dashboardApi = {
 getSummary: async (): Promise<DashboardSummary> => {
 const res = await apiClient.get<DashboardSummary>('/dashboard');
 return res.data;
 },
};
