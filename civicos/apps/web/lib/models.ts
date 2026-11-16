export type Feature = { key: string; label: string; higher_is_better: boolean | null };
export type Group = { cluster: number; label: string; wards: string[]; mean: Record<string, number>; z: Record<string, number> };
export type FamilyMetrics = {
  label: string;
  series: number;
  backtest_years: number[];
  chosen: string;
  mape_pct: Record<string, number>;
  mae: Record<string, number>;
  interval_pct: number;
  improvement_vs_naive_pct: number | null;
};

export type Model<P> = {
  id: string;
  name: string;
  kind: "clustering" | "forecast";
  method: string;
  description: string;
  params: P;
  metrics: Record<string, unknown>;
  trained_on: string;
  trained_at: string;
};

export type ClusterParams = { k: number; features: Feature[]; groups: Group[] };
export type ForecastParams = { methods: Record<string, string>; backtest_years: number[]; families: Record<string, FamilyMetrics> };

export type Forecast = { year: number; value: number; lower: number; upper: number; method: string; family: string; category: string | null };

export type MlData = {
  models: { clustering?: Model<ClusterParams>; forecast?: Model<ForecastParams> };
  wards: { code: string; name: string; cluster: number; features: Record<string, number>; z: Record<string, number> }[];
  zone: { id: string; code: string; name: string } | null;
  issue: string | null;
  history: { year: number; value: number }[];
  forecast: Forecast | null;
  ward_forecasts: { code: string; name: string; value: number; lower: number; upper: number; last: number | null }[];
  issues_with_forecasts: string[];
  ward_issues: string[];
};
