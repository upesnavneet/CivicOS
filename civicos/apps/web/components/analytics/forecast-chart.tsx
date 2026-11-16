"use client";

import { CartesianGrid, ComposedChart, ErrorBar, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmt } from "@/lib/dashboard";
import { SERIES } from "@/lib/chart-colors";
import type { Forecast } from "@/lib/models";

type Row = { year: number; actual: number | null; forecast: number | null; range: [number, number] | null; lower?: number; upper?: number };

/** Ten published years as a solid line; the 2026 forecast as a dashed step from 2025 with its 80% range as an error bar. */
export function ForecastChart({ history, forecast }: { history: { year: number; value: number }[]; forecast: Forecast | null }) {
  const rows: Row[] = history.map((h) => ({ year: h.year, actual: h.value, forecast: null, range: null }));
  if (forecast && rows.length) {
    rows[rows.length - 1].forecast = rows[rows.length - 1].actual;      // dashed line starts at the last real year
    rows[rows.length - 1].range = [0, 0];
    rows.push({
      year: forecast.year, actual: null, forecast: forecast.value,
      range: [forecast.value - forecast.lower, forecast.upper - forecast.value], lower: forecast.lower, upper: forecast.upper,
    });
  }
  const tick = { fill: "var(--color-muted)", fontSize: 12 };

  return (
    <div>
      <ul className="mb-2 flex flex-wrap gap-x-4 text-xs text-muted">
        <li className="flex items-center gap-1.5"><span className="inline-block h-0.5 w-4 rounded" style={{ background: SERIES.one }} />Published</li>
        <li className="flex items-center gap-1.5">
          <span className="inline-block h-0 w-4 border-t-2 border-dashed" style={{ borderColor: SERIES.two }} />
          Forecast with 80% range
        </li>
      </ul>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={rows} margin={{ top: 8, right: 16, bottom: 0, left: 0 }}>
            <CartesianGrid stroke="var(--color-line)" vertical={false} />
            <XAxis dataKey="year" tick={tick} tickLine={false} axisLine={{ stroke: "var(--color-line)" }} />
            <YAxis tick={tick} tickLine={false} axisLine={false} width={60} domain={[0, "auto"]} tickFormatter={(v) => fmt.int(v)} />
            <Tooltip
              cursor={{ stroke: "var(--color-faint)", strokeWidth: 1 }}
              content={({ active, payload, label }) => {
                if (!active || !payload?.length) return null;
                const r = payload[0].payload as Row;
                return (
                  <div className="rounded-lg border border-line bg-base px-3 py-2 text-xs shadow-lg">
                    <p className="mb-1 font-medium text-ink">{label}</p>
                    {r.actual != null ? <p className="text-muted">Published <span className="ml-2 font-medium tabular-nums text-ink">{fmt.int(r.actual)}</span></p> : null}
                    {r.actual == null && r.forecast != null ? (
                      <>
                        <p className="text-muted">Forecast <span className="ml-2 font-medium tabular-nums text-ink">{fmt.int(r.forecast)}</span></p>
                        <p className="text-muted">80% range <span className="ml-2 tabular-nums text-ink">{fmt.int(r.lower)} to {fmt.int(r.upper)}</span></p>
                      </>
                    ) : null}
                  </div>
                );
              }}
            />
            <Line type="linear" dataKey="actual" stroke={SERIES.one} strokeWidth={2} dot={{ r: 3, fill: SERIES.one, strokeWidth: 0 }} activeDot={{ r: 4, stroke: "var(--color-panel)", strokeWidth: 2 }} isAnimationActive={false} />
            <Line type="linear" dataKey="forecast" stroke={SERIES.two} strokeWidth={2} strokeDasharray="5 4" dot={{ r: 4, fill: SERIES.two, strokeWidth: 0 }} isAnimationActive={false} connectNulls>
              <ErrorBar dataKey="range" width={10} strokeWidth={1.5} stroke={SERIES.two} direction="y" />
            </Line>
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
