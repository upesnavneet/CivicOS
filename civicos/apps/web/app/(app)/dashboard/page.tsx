import type { Metadata } from "next";
import Link from "next/link";
import { Activity, CheckCircle2, Clock, Droplets, HeartPulse, Hourglass, MapPinned, Trash2, Wind } from "lucide-react";
import { BarSeriesChart, ChartCard, EmptyChart, LineSeriesChart } from "@/components/dashboard/charts";
import { AqiGrid, Funnel, HealthIndex, KpiCard, Stat } from "@/components/dashboard/panels";
import { FilterBar } from "@/components/filter-bar";
import { requireSession } from "@/lib/auth";
import { SERIES } from "@/lib/chart-colors";
import { cite, fmt, MONTHS, type DashboardData } from "@/lib/dashboard";
import { parseFilters } from "@/lib/filters";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = { title: "Dashboard" };

const SWM = "Solid Waste Management (SWM)";

export default async function DashboardPage({ searchParams }: PageProps<"/dashboard">) {
  const session = await requireSession();
  const filters = parseFilters(await searchParams);
  const supabase = await createClient();

  const [{ data, error }, zones, city] = await Promise.all([
    supabase.rpc("dashboard_data", { p_year: filters.year, p_zone: filters.zone, p_issue: filters.issue }),
    supabase.from("city_zones").select("id, name").order("code"),
    supabase.from("cities").select("name").limit(1).maybeSingle(),
  ]);

  const d = data as DashboardData | null;
  const cityName = city.data?.name ?? "City";
  const title = <h1 className="text-2xl font-semibold tracking-tight">City Intelligence Dashboard</h1>;

  if (error || !d) {
    return (
      <div className="mx-auto max-w-6xl space-y-6">
        {title}
        <Notice title="The dashboard query failed">
          {error?.message ?? "No data returned."} Check that every migration in supabase/migrations has been run.
        </Notice>
      </div>
    );
  }

  if (!d.meta.has_data) {
    return (
      <div className="mx-auto max-w-6xl space-y-6">
        {title}
        <Notice title="This workspace has no published data yet">
          {session.role === "city_admin" ? (
            <>
              CivicOS shows only real, published figures and never generates data. To load the Mumbai dataset
              (BMC figures published by Praja Foundation), run this in the Supabase SQL Editor and refresh:
              <code className="mt-3 block overflow-x-auto rounded-lg border border-line bg-base p-3 font-mono text-xs text-ink">
                select app.load_mumbai_data(&apos;{session.orgId}&apos;);
              </code>
            </>
          ) : (
            "Ask your City Administrator to load a dataset for this workspace."
          )}
        </Notice>
      </div>
    );
  }

  const { kpis: k, meta, sources } = d;
  const year = meta.year;
  const scope = meta.zone ? meta.zone.name : cityName;
  const issueLabel = meta.issue ?? "All issues";
  const closureYears = meta.closure_years ?? [];
  const notPublished = closureYears.length ? `Published for ${closureYears.join(", ")} only` : "Not published at this level";
  const change = k.registered != null && k.registered_prev ? (100 * (k.registered - k.registered_prev)) / k.registered_prev : null;

  // which table each figure was read from
  const trendSrc = meta.zone ? (meta.issue === SWM ? "p26-t39" : meta.issue === "Drainage" ? "p26-t41" : "p26-t43") : meta.issue ? "p26-t1" : "p26-t43";
  const closureSrc = meta.issue === SWM ? "p26-t40" : meta.issue === "Drainage" ? "p26-t42" : year === 2024 ? "p25-t45" : "p26-t3";
  const wardCountSrc = meta.issue === SWM ? "p26-t39" : meta.issue === "Drainage" ? "p26-t41" : "p26-t43";

  const wards = d.wards;
  const withClosure = wards.filter((w) => w.closed_pct != null);
  const withWaste = wards.filter((w) => w.waste_tpd != null);
  const withWater = wards.filter((w) => w.water_hours != null);
  const withHealth = [...wards].filter((w) => w.health_score != null).sort((a, b) => a.health_score! - b.health_score!);
  const waterYear = withWater[0]?.water_hours_year ?? k.water_hours_year;
  const bal = d.water.balance;
  const goodAir = d.aqi.ward_days.filter((x) => x.level === "Good" || x.level === "Satisfactory").reduce((a, x) => a + x.days, 0);
  const col = (key: string, label: string) => ({ key, label, color: SERIES.one });

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        {title}
        <p className="mt-1 text-sm text-muted">
          {scope} · {year} · {issueLabel} · published BMC figures as reported by Praja Foundation
        </p>
      </div>

      <FilterBar filters={filters} city={cityName} year={year} years={meta.years} zones={zones.data ?? []} issues={meta.ward_issues ?? []} />
      <p className="-mt-3 text-xs text-faint">
        The reports break complaints down by ward for all issues together and for {(meta.ward_issues ?? []).join(" and ")} only, so those are the issue filters.
        Water, waste and air figures are not affected by the issue filter.
      </p>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard
          icon={Activity} label="Complaints registered" value={fmt.int(k.registered)}
          note={change == null ? `In ${year}` : `${change >= 0 ? "+" : ""}${change.toFixed(0)}% against ${year - 1}`}
        />
        <KpiCard icon={CheckCircle2} label="Complaints closed" value={fmt.one(k.closed_pct)} unit="%" note={k.closed == null ? notPublished : `${fmt.int(k.closed)} closed`} />
        <KpiCard icon={Hourglass} label="Complaints not closed" value={fmt.int(k.pending)} note={k.pending == null ? notPublished : "Registered minus closed"} />
        <KpiCard icon={Clock} label="Average days to close" value={fmt.int(k.avg_days)} unit="days" note={k.avg_days == null ? notPublished : `In ${year}`} />
        <KpiCard icon={Trash2} label="Waste lifted" value={fmt.int(k.waste_tpd)} unit="t / day" note={k.waste_tpd == null ? "Published for 2021 to 2025" : `Average in ${year}`} />
        <KpiCard icon={Droplets} label="Water supply" value={fmt.two(k.water_hours)} unit="hrs / day" note={k.water_hours == null ? "Not published" : `Average in ${k.water_hours_year}`} />
        {meta.zone ? (
          <KpiCard
            icon={Wind} label="Good or satisfactory air" value={d.aqi.ward_days.length ? fmt.int(goodAir) : "—"} unit="days"
            note={d.aqi.ward_days.length ? "Of 365 days in 2025" : "No monitoring station in this ward"}
          />
        ) : (
          <KpiCard icon={Wind} label="Average AQI" value={fmt.int(k.aqi_avg)} note={`Mean of ${year}'s monthly averages`} />
        )}
        <KpiCard icon={HeartPulse} label="City health score" value={fmt.one(k.health_score)} unit="/ 100" note={`Prototype index, ${d.health.year ?? ""}`} />
      </div>

      <ChartCard
        title={`City Health Index: ${scope}`}
        question="How healthy is the city overall, and what is raising or lowering the score?"
        note="Prototype index for demonstration, not an official municipal rating. A component with no published figure for a ward is left out and the other weights are scaled up."
        source={`Computed from: ${cite(sources, ["p26-t3", "p25-t4", "p25-t7", "p26-t30"]).replace("Source: ", "")}`}
        table={{ columns: ["Ward", "Health score"], rows: withHealth.map((w) => [w.name, w.health_score]) }}
      >
        <HealthIndex health={d.health} />
        <div className="mt-6">
          <p className="mb-2 text-xs font-medium text-muted">Score by ward, lowest first</p>
          <BarSeriesChart data={withHealth.map((w) => ({ ward: w.code, score: w.health_score }))} xKey="ward" series={col("score", "Health score")} />
        </div>
      </ChartCard>

      <div className="grid gap-4 lg:grid-cols-2">
        <ChartCard
          title={`Complaints registered per year: ${scope}`}
          question="Are civic complaints rising?"
          source={cite(sources, [trendSrc])}
          table={{ columns: ["Year", "Complaints registered"], rows: d.complaints_by_year.map((r) => [r.year, r.registered]) }}
        >
          {d.complaints_by_year.length ? (
            <LineSeriesChart data={d.complaints_by_year} xKey="year" xType="year" series={[col("registered", "Complaints registered")]} />
          ) : (
            <EmptyChart message="Not published for this ward and issue." />
          )}
        </ChartCard>

        <ChartCard
          title={`Registered against closed, ${year}`}
          question="How many of the year's complaints were closed?"
          note="The reports publish registered and closed counts only, not the stages in between."
          source={cite(sources, [meta.zone || meta.issue ? closureSrc : year === 2024 ? "p25-t45" : "p26-t3"])}
        >
          {k.registered != null && k.closed != null ? <Funnel registered={k.registered} closed={k.closed} /> : <EmptyChart message={`${notPublished}.`} />}
        </ChartCard>

        <ChartCard
          className="lg:col-span-2"
          title={`Complaints by issue, ${cityName}, ${year}`}
          question="What do citizens complain about most?"
          note="City-wide, whatever ward is selected: the reports do not break every issue down by ward."
          source={cite(sources, ["p26-t1", "p26-t2"])}
          table={{
            columns: ["Issue", "Registered", "Closed", "Closed %", "Avg days to close"],
            rows: d.issues.map((r) => [r.issue, r.registered, r.closed, r.closed_pct, r.avg_days]),
          }}
        >
          <BarSeriesChart data={d.issues} xKey="issue" direction="row" labelWidth={210} height={d.issues.length * 24 + 30} series={col("registered", "Complaints registered")} />
        </ChartCard>

        <ChartCard
          title={`Complaints per 10,000 residents by ward, ${year}`}
          question="Where are civic issues concentrated, allowing for population?"
          note="Uses the 2025 ward populations printed in the report for every year."
          source={cite(sources, [wardCountSrc])}
          table={{ columns: ["Ward", "Population (2025)", "Registered", "Per 10,000 residents"], rows: wards.map((w) => [w.name, w.population, w.registered, w.per_10k]) }}
        >
          {wards.some((w) => w.per_10k != null) ? (
            <BarSeriesChart data={wards.map((w) => ({ ward: w.code, per_10k: w.per_10k }))} xKey="ward" series={col("per_10k", "Complaints per 10,000 residents")} />
          ) : (
            <EmptyChart />
          )}
          <Link href={`/map?year=${year}`} className="mt-3 inline-flex items-center gap-1.5 text-xs text-accent hover:underline">
            <MapPinned className="size-3.5" aria-hidden="true" />
            See this on the ward map
          </Link>
        </ChartCard>

        <ChartCard
          title={`Average days to close a complaint by ward, ${year}`}
          question="Which wards resolve complaints fastest?"
          source={cite(sources, [closureSrc])}
          table={{ columns: ["Ward", "Registered", "Closed", "Closed %", "Avg days to close"], rows: withClosure.map((w) => [w.name, w.registered, w.closed, w.closed_pct, w.avg_days]) }}
        >
          {withClosure.length ? (
            <BarSeriesChart data={withClosure.map((w) => ({ ward: w.code, days: w.avg_days }))} xKey="ward" unit="days" series={col("days", "Average days to close")} />
          ) : (
            <EmptyChart message={`${notPublished}.`} />
          )}
        </ChartCard>

        <ChartCard
          title={`Average AQI by month, ${year} and ${year - 1}`}
          question="When is the air worst, and is it better than last year?"
          note="City-wide monthly averages. A higher AQI means worse air."
          source={cite(sources, ["p26-t29"])}
          table={{ columns: ["Month", String(year), String(year - 1)], rows: d.aqi.months.map((m) => [MONTHS[m.month - 1], m.current, m.previous]) }}
        >
          {d.aqi.months.length ? (
            <LineSeriesChart
              data={d.aqi.months} xKey="month" xType="month" unit="AQI"
              series={[
                { key: "current", label: String(year), color: SERIES.one },
                { key: "previous", label: String(year - 1), color: SERIES.two },
              ]}
            />
          ) : (
            <EmptyChart />
          )}
        </ChartCard>

        <ChartCard title="Average AQI by month, 2016 to 2025" question="How has air quality changed over ten years?" source={cite(sources, ["p26-t29"])}>
          <AqiGrid grid={d.aqi.grid} />
        </ChartCard>

        <ChartCard
          title={`Waste lifted by ward, tonnes per day, ${year}`}
          question="Which wards generate the most waste?"
          source={cite(sources, ["p26-t37", "p26-t11"])}
          table={{ columns: ["Ward", "Tonnes per day", "Kg per person per day (2025)"], rows: withWaste.map((w) => [w.name, w.waste_tpd, w.waste_per_capita]) }}
        >
          {withWaste.length ? (
            <BarSeriesChart data={withWaste.map((w) => ({ ward: w.code, tpd: w.waste_tpd }))} xKey="ward" unit="t/day" series={col("tpd", "Waste lifted")} />
          ) : (
            <EmptyChart message="Ward waste figures are published for 2021 to 2025." />
          )}
        </ChartCard>

        <ChartCard
          title={`Waste lifted per year, tonnes per day: ${scope}`}
          question="Is the amount of waste growing?"
          note={meta.zone ? undefined : "The city total includes waste handled at transfer stations, which the report lists separately from wards from 2023."}
          source={cite(sources, ["p26-t37"])}
          table={{ columns: ["Year", "Tonnes per day"], rows: d.waste_by_year.map((r) => [r.year, r.tonnes_per_day]) }}
        >
          {d.waste_by_year.length ? (
            <BarSeriesChart data={d.waste_by_year} xKey="year" unit="t/day" series={col("tonnes_per_day", "Waste lifted")} />
          ) : (
            <EmptyChart />
          )}
        </ChartCard>

        <ChartCard
          title={`Water supply hours per day by ward, ${waterYear ?? ""}`}
          question="Which wards get the least water supply?"
          source={cite(sources, ["p25-t4"])}
          table={{ columns: ["Ward", "Average hours per day"], rows: withWater.map((w) => [w.name, w.water_hours]) }}
        >
          {withWater.length ? (
            <BarSeriesChart data={withWater.map((w) => ({ ward: w.code, hours: w.water_hours }))} xKey="ward" unit="hrs" series={col("hours", "Supply hours per day")} />
          ) : (
            <EmptyChart />
          )}
        </ChartCard>

        <ChartCard
          title={`Drinking-water samples found unfit, %: ${scope}`}
          question="Is drinking-water quality improving?"
          source={cite(sources, ["p25-t7"])}
          table={{ columns: ["Year", "Unfit samples %"], rows: d.water.unfit_by_year.map((r) => [r.year, r.pct]) }}
        >
          {d.water.unfit_by_year.length ? (
            <BarSeriesChart data={d.water.unfit_by_year} xKey="year" unit="%" series={col("pct", "Unfit samples")} />
          ) : (
            <EmptyChart />
          )}
        </ChartCard>

        {bal ? (
          <ChartCard
            className="lg:col-span-2"
            title={`${cityName}'s water balance, 2023-24, million litres per day`}
            question="How far does supply fall short of demand?"
            source={cite(sources, ["p25-t1"])}
          >
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              <Stat label="Yield from sources" value={fmt.int(bal.water_yield_mld)} unit="MLD" />
              <Stat label="Lost en route" value={fmt.int(bal.water_enroute_loss_mld)} unit="MLD" />
              <Stat label="Supplied to the city" value={fmt.int(bal.water_supply_mld)} unit="MLD" />
              <Stat label="Demand" value={fmt.int(bal.water_demand_mld)} unit="MLD" />
              <Stat label="Shortfall" value={fmt.int(bal.water_gap_mld)} unit={`MLD · ${Math.round((100 * bal.water_gap_mld) / bal.water_demand_mld)}%`} />
            </div>
          </ChartCard>
        ) : null}
      </div>

      <section className="rounded-xl border border-line bg-panel p-5">
        <h2 className="text-sm font-medium">Data sources</h2>
        <p className="mt-1 text-xs text-muted">
          Every figure on this page was read from the tables below and checked against each table&apos;s own total row. Nothing is estimated or generated.
        </p>
        <ul className="mt-4 grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
          {Object.entries(sources)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([id, s]) => (
              <li key={id} className="text-muted">
                {s.url ? (
                  <a href={s.url} target="_blank" rel="noreferrer" className="text-ink hover:text-accent hover:underline">
                    {s.title}
                  </a>
                ) : (
                  <span className="text-ink">{s.title}</span>
                )}
                <span className="block text-faint">
                  {s.publisher}
                  {s.table ? `, ${s.table}` : ""}
                  {s.page ? `, p. ${s.page}` : ""}
                  {s.note ? ` · ${s.note}` : ""}
                </span>
              </li>
            ))}
        </ul>
      </section>
    </div>
  );
}

function Notice({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-line bg-panel p-6">
      <h2 className="text-sm font-medium">{title}</h2>
      <div className="mt-2 text-sm leading-relaxed text-muted">{children}</div>
    </div>
  );
}
