export type Ward = {
  code: string;
  name: string;
  population: number | null;
  registered: number | null;
  closed: number | null;
  closed_pct: number | null;
  avg_days: number | null;
  per_10k: number | null;
  waste_tpd: number | null;
  waste_per_capita: number | null;
  water_hours: number | null;
  water_hours_year: number | null;
  water_unfit_pct: number | null;
  water_unfit_year: number | null;
  air_good_days: number | null;
  air_measured_days: number | null;
  air_year: number | null;
  slum_pct: number | null;
  health_score: number | null;
  ward_group: number | null;
};

export type Source = { publisher: string; report: string; table: string | null; page: number | null; title: string; url: string | null; note: string | null };

export type DashboardData = {
  meta: {
    has_data: boolean;
    year: number;
    issue: string | null;
    years: number[];
    zone: { id: string; code: string; name: string; population: number | null } | null;
    ward_issues: string[] | null;
    closure_years: number[] | null;
  };
  kpis: {
    registered: number | null;
    registered_prev: number | null;
    closed: number | null;
    closed_pct: number | null;
    pending: number | null;
    avg_days: number | null;
    waste_tpd: number | null;
    water_unfit_pct: number | null;
    aqi_avg: number | null;
    water_hours: number | null;
    water_hours_year: number | null;
    health_score: number | null;
  };
  complaints_by_year: { year: number; registered: number }[];
  issues: { issue: string; registered: number; closed: number | null; closed_pct: number | null; avg_days: number | null }[];
  wards: Ward[];
  aqi: {
    months: { month: number; current: number | null; previous: number | null }[];
    grid: { year: number; values: number[] }[];
    ward_days: { level: string; days: number }[];
  };
  waste_by_year: { year: number; tonnes_per_day: number }[];
  water: {
    balance: Record<string, number> | null;
    unfit_by_year: { year: number; pct: number }[];
    zones_by_hours: { band: string; zones: number }[];
  };
  health: { score: number | null; year: number | null; components: Record<string, number> | null; weights: Record<string, number> | null };
  sources: Record<string, Source>;
};

export type Option = { id: string; name: string };

const nf = new Intl.NumberFormat("en-IN");
const nf1 = new Intl.NumberFormat("en-IN", { maximumFractionDigits: 1 });
const nf2 = new Intl.NumberFormat("en-IN", { maximumFractionDigits: 2 });

export const fmt = {
  int: (n: number | null | undefined) => (n == null ? "—" : nf.format(Math.round(n))),
  one: (n: number | null | undefined) => (n == null ? "—" : nf1.format(n)),
  two: (n: number | null | undefined) => (n == null ? "—" : nf2.format(n)),
};

export const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export const COMPONENT_LABEL: Record<string, string> = {
  complaint_closure: "Complaints closed",
  resolution_speed: "Speed of resolution",
  water_supply: "Hours of water supply",
  water_quality: "Drinking-water quality",
  air_quality: "Good-air days",
};

export const COMPONENT_HOW: Record<string, string> = {
  complaint_closure: "Share of the year's complaints that were closed.",
  resolution_speed: "100 at zero days to close, 0 at 60 days or more.",
  water_supply: "Average supply hours per day out of 24.",
  water_quality: "100 minus 20 points per 1% of samples found unfit.",
  air_quality: "Share of monitored days rated Good or Satisfactory.",
};

/** "Praja Foundation, 2026 report, Table 43, p. 100" for a list of source ids. */
export function cite(sources: Record<string, Source>, ids: string[]): string {
  const parts = ids
    .map((id) => sources[id])
    .filter(Boolean)
    .map((s) => {
      const year = s.report.match(/\((\d{4})\)/)?.[1];
      return `${s.publisher}${year ? ` ${year} report` : ""}${s.table ? `, ${s.table}` : ""}${s.page ? `, p. ${s.page}` : ""}`;
    });
  return parts.length ? `Source: ${parts.join("; ")}.` : "";
}
