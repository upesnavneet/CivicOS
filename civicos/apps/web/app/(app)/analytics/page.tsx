import type { Metadata } from "next";
import Link from "next/link";
import { MapPinned } from "lucide-react";
import { ForecastChart } from "@/components/analytics/forecast-chart";
import { GroupProfile } from "@/components/analytics/group-profile";
import { SeriesPicker } from "@/components/analytics/series-picker";
import { ChartCard } from "@/components/dashboard/charts";
import { requireSession } from "@/lib/auth";
import { GROUP_COLORS } from "@/lib/chart-colors";
import { fmt } from "@/lib/dashboard";
import { parseFilters } from "@/lib/filters";
import type { MlData } from "@/lib/models";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = { title: "Analytics" };

export default async function AnalyticsPage({ searchParams }: PageProps<"/analytics">) {
  await requireSession();
  const filters = parseFilters(await searchParams);
  const supabase = await createClient();

  const [{ data, error }, zones] = await Promise.all([
    supabase.rpc("ml_data", { p_zone: filters.zone, p_issue: filters.issue }),
    supabase.from("city_zones").select("id, name").order("code"),
  ]);
  const d = data as MlData | null;

  const header = (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">Ward patterns and forecasts</h1>
      <p className="mt-1 text-sm text-muted">Two models trained on the published ward figures. Each shows how it was built and how accurate it was.</p>
    </div>
  );

  if (error || !d) {
    return (
      <div className="mx-auto max-w-6xl space-y-6">
        {header}
        <p className="rounded-xl border border-line bg-panel p-6 text-sm text-muted">The models query failed: {error?.message ?? "no data returned"}.</p>
      </div>
    );
  }
  const cm = d.models.clustering;
  const fm = d.models.forecast;
  if (!cm || !fm) {
    return (
      <div className="mx-auto max-w-6xl space-y-6">
        {header}
        <p className="rounded-xl border border-line bg-panel p-6 text-sm text-muted">No models have been loaded for this workspace. They load with the Mumbai dataset.</p>
      </div>
    );
  }

  const features = cm.params.features;
  const groups = [...cm.params.groups].sort((a, b) => a.cluster - b.cluster);
  const cityMean = Object.fromEntries(features.map((f) => [f.key, d.wards.reduce((a, w) => a + (w.features[f.key] ?? 0), 0) / d.wards.length]));
  const silhouette = cm.metrics.silhouette as number;

  const fc = d.forecast;
  const fam = fc ? fm.params.families[fc.family] : null;
  const last = d.history.at(-1);
  const scope = d.zone ? d.zone.name : "Whole city";
  const families = Object.entries(fm.params.families);
  const methodOrder = ["naive", "mean3", "trend"].filter((m) => m in fm.params.methods);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      {header}

      {/* ---------------- ward groups ---------------- */}
      <ChartCard
        title={`${cm.name}: ${groups.length} groups of wards`}
        question="Which wards look alike once complaints, resolution, water and waste are taken together?"
        note={`${cm.description} Silhouette score ${silhouette.toFixed(2)} (from −1 to 1; above 0.25 is weak but real structure). Solutions with 3 to 5 groups scored lower or left a group with a single ward.`}
        source={`Method: ${cm.method}. Trained on ${cm.trained_on}.`}
        table={{
          columns: ["Ward", "Group", ...features.map((f) => f.label)],
          rows: d.wards.map((w) => [w.name, w.cluster, ...features.map((f) => w.features[f.key])]),
        }}
      >
        <div className="mb-5 grid gap-3 sm:grid-cols-2">
          {groups.map((g) => (
            <div key={g.cluster} className="rounded-lg border border-line p-4">
              <p className="flex items-center gap-2 text-sm font-medium text-ink">
                <span className="inline-block size-3 rounded-sm" style={{ background: GROUP_COLORS[g.cluster - 1] }} />
                Group {g.cluster}: {g.label}
              </p>
              <p className="mt-2 flex flex-wrap gap-1.5">
                {g.wards.map((w) => (
                  <span key={w} className="rounded border border-line px-1.5 py-0.5 font-mono text-xs text-muted">{w}</span>
                ))}
              </p>
            </div>
          ))}
        </div>
        <GroupProfile groups={groups} features={features} cityMean={cityMean} />
        <Link href="/map" className="mt-4 inline-flex items-center gap-1.5 text-xs text-accent hover:underline">
          <MapPinned className="size-3.5" aria-hidden="true" />
          See the groups on the map (shade wards by “Ward group”)
        </Link>
      </ChartCard>

      {/* ---------------- forecasts ---------------- */}
      <ChartCard
        title={`Complaints registered, 2016 to 2025, and the 2026 forecast: ${scope}${d.issue ? `, ${d.issue}` : ""}`}
        question="How many complaints should the city plan for next year?"
        note={
          fc && fam
            ? `Method: ${fm.params.methods[fc.method]}. It had the lowest error when tested on ${fam.backtest_years.join(", ")} across ${fam.series === 1 ? "this one series" : `${fam.series} series in this family`} (${fam.label.toLowerCase()})${fam.series === 1 ? ", only four test forecasts, so treat the choice as tentative" : ""}. In that test, 80% of forecasts were within ±${fam.interval_pct}% of the real figure, which sets the range shown.`
            : undefined
        }
        source={`Trained on ${fm.trained_on}.`}
        table={{ columns: ["Year", "Complaints"], rows: [...d.history.map((h) => [h.year, h.value] as (string | number)[]), ...(fc ? [[`${fc.year} (forecast)`, `${fmt.int(fc.value)} (${fmt.int(fc.lower)} to ${fmt.int(fc.upper)})`]] : [])] }}
      >
        <div className="mb-4 flex flex-wrap items-end justify-between gap-4">
          <SeriesPicker zone={filters.zone} issue={filters.issue} wards={zones.data ?? []} cityIssues={d.issues_with_forecasts} wardIssues={d.ward_issues} />
          {fc ? (
            <div className="text-right">
              <p className="text-xs text-muted">2026 forecast</p>
              <p className="text-2xl font-semibold tabular-nums">{fmt.int(fc.value)}</p>
              <p className="text-xs tabular-nums text-muted">
                80% range {fmt.int(fc.lower)} to {fmt.int(fc.upper)}
                {last ? ` · ${last.year}: ${fmt.int(last.value)}` : ""}
              </p>
            </div>
          ) : null}
        </div>
        {d.history.length ? (
          <ForecastChart history={d.history} forecast={fc} />
        ) : (
          <p className="py-10 text-center text-sm text-faint">No published series for this ward and issue.</p>
        )}
      </ChartCard>

      <div className="grid gap-4 lg:grid-cols-2">
        <ChartCard
          title="How accurate were the forecasts?"
          question="Does the chosen method beat simply repeating last year's figure?"
          note="Average error as a share of the real figure (MAPE), forecasting each of 2022 to 2025 from the years before it. Lower is better. Where last year's value wins, it is the method used: a fancier method would be worse."
        >
          <div className="overflow-x-auto">
            <table className="w-full min-w-[460px] text-left text-xs tabular-nums">
              <thead className="text-muted">
                <tr>
                  <th className="py-2 pr-3 font-medium">Series</th>
                  {methodOrder.map((k) => (
                    <th key={k} className="py-2 pr-3 text-right font-medium" title={fm.params.methods[k]}>
                      {k === "naive" ? "Last year" : k === "mean3" ? "3-yr avg" : "Trend"}
                    </th>
                  ))}
                  <th className="py-2 text-right font-medium">80% range</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {families.map(([key, f]) => (
                  <tr key={key}>
                    <td className="py-2 pr-3 text-ink">
                      {f.label}
                      <span className="block text-faint">{f.series} series × {f.backtest_years.length} test years</span>
                    </td>
                    {methodOrder.map((m) => (
                      <td key={m} className={`py-2 pr-3 text-right ${m === f.chosen ? "font-semibold text-accent" : "text-muted"}`}>
                        {f.mape_pct[m].toFixed(1)}%
                      </td>
                    ))}
                    <td className="py-2 text-right text-muted">±{f.interval_pct}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-xs text-muted">The chosen method for each series is highlighted.</p>
        </ChartCard>

        <ChartCard
          title={`2026 forecast by ward${d.issue ? `, ${d.issue}` : ""}`}
          question="Which wards should expect more complaints next year?"
          note={d.ward_forecasts.length ? undefined : "Ward forecasts exist for all issues together, solid waste and drainage only."}
        >
          {d.ward_forecasts.length ? (
            <div className="max-h-[420px] overflow-auto">
              <table className="w-full text-left text-xs tabular-nums">
                <thead className="sticky top-0 bg-panel text-muted">
                  <tr>
                    <th className="py-2 pr-3 font-medium">Ward</th>
                    <th className="py-2 pr-3 text-right font-medium">2025</th>
                    <th className="py-2 pr-3 text-right font-medium">2026 forecast</th>
                    <th className="py-2 pr-3 text-right font-medium">80% range</th>
                    <th className="py-2 text-right font-medium">Change</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {d.ward_forecasts.map((w) => {
                    const ch = w.last ? (100 * (w.value - w.last)) / w.last : null;
                    return (
                      <tr key={w.code}>
                        <td className="py-1.5 pr-3 text-ink">{w.name}</td>
                        <td className="py-1.5 pr-3 text-right text-muted">{fmt.int(w.last)}</td>
                        <td className="py-1.5 pr-3 text-right font-medium text-ink">{fmt.int(w.value)}</td>
                        <td className="py-1.5 pr-3 text-right text-muted">{fmt.int(w.lower)} to {fmt.int(w.upper)}</td>
                        <td className="py-1.5 text-right text-muted">{ch == null ? "—" : `${ch > 0 ? "+" : ""}${ch.toFixed(0)}%`}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}
        </ChartCard>
      </div>

      <section className="rounded-xl border border-line bg-panel p-5 text-xs leading-relaxed text-muted">
        <h2 className="text-sm font-medium text-ink">Limits of these models</h2>
        <ul className="mt-2 list-disc space-y-1 pl-4">
          <li>Each series has ten yearly figures, and 2020 and 2021 are pandemic years. That is too little history for anything more complex than the three methods compared here.</li>
          <li>The forecasts assume next year behaves like the recent past. A one-off event, such as ward S&apos;s jump from 6,221 complaints in 2024 to 13,116 in 2025, will not be predicted and is only partly carried forward.</li>
          <li>Ward groups describe 2025 (water 2024) and depend on which indicators are included. They show patterns, not causes.</li>
          <li>Both models were trained on {fm.trained_at} from the published figures only. Retrain them when a new annual report is loaded.</li>
        </ul>
      </section>
    </div>
  );
}
