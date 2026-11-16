"use client";

import type { ReactNode } from "react";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, LabelList, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { fmt, MONTHS } from "@/lib/dashboard";

export type Series = { key: string; label: string; color: string };
type Row = Record<string, string | number | null>;
type XType = "year" | "month" | "category";

const GRID = "var(--color-line)";
const TICK = { fill: "var(--color-muted)", fontSize: 12 };
/** Whole numbers for counts, two decimals when the axis runs in fractions (for example 0.25%). */
const axisNumber = (v: number) => (Number.isInteger(v) ? fmt.int(v) : fmt.two(v));

function formatX(value: string | number, xType: XType): string {
  if (xType === "month") return MONTHS[Number(value) - 1] ?? String(value);
  return String(value);
}

type TipProps = {
  active?: boolean;
  label?: string | number;
  payload?: { dataKey?: string | number; value?: number | string | null; color?: string }[];
  series: Series[];
  unit?: string;
  xType: XType;
};

function Tip({ active, label, payload, series, unit, xType }: TipProps) {
  if (!active || !payload?.length || label == null) return null;
  return (
    <div className="rounded-lg border border-line bg-base px-3 py-2 text-xs shadow-lg">
      <p className="mb-1 font-medium text-ink">{formatX(label, xType)}</p>
      {payload.map((p) => {
        const s = series.find((x) => x.key === p.dataKey);
        return (
          <p key={String(p.dataKey)} className="flex items-center gap-2 text-muted">
            <span className="inline-block size-2 rounded-sm" style={{ background: s?.color }} />
            {s?.label}
            <span className="ml-auto pl-3 font-medium tabular-nums text-ink">
              {p.value == null ? "—" : fmt.one(Number(p.value))}
              {unit ? ` ${unit}` : ""}
            </span>
          </p>
        );
      })}
    </div>
  );
}

function LegendRow({ series }: { series: Series[] }) {
  if (series.length < 2) return null; // one series: the title already names it
  return (
    <ul className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
      {series.map((s) => (
        <li key={s.key} className="flex items-center gap-1.5">
          <span className="inline-block h-0.5 w-4 rounded" style={{ background: s.color }} />
          {s.label}
        </li>
      ))}
    </ul>
  );
}

/** Time or hour series. One zero-based series renders as a line over a light wash; otherwise plain lines (with a legend for two or more). */
export function LineSeriesChart({
  data, xKey, xType, series, unit, zeroBased = true,
}: { data: Row[]; xKey: string; xType: XType; series: Series[]; unit?: string; zeroBased?: boolean }) {
  const common = {
    data,
    margin: { top: 8, right: 12, bottom: 0, left: 0 },
  };
  const axes = (
    <>
      <CartesianGrid stroke={GRID} vertical={false} />
      <XAxis dataKey={xKey} tick={TICK} tickLine={false} axisLine={{ stroke: GRID }} minTickGap={16} tickFormatter={(v) => formatX(v, xType)} />
      <YAxis
        tick={TICK} tickLine={false} axisLine={false} width={60}
        domain={zeroBased ? [0, "auto"] : ["auto", "auto"]}
        tickFormatter={axisNumber}
      />
      <Tooltip
        cursor={{ stroke: "var(--color-faint)", strokeWidth: 1 }}
        content={<Tip series={series} unit={unit} xType={xType} />}
      />
    </>
  );
  const dot = { r: 4, stroke: "var(--color-panel)", strokeWidth: 2 };

  return (
    <div>
      <LegendRow series={series} />
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          {series.length === 1 && zeroBased ? (
            <AreaChart {...common}>
              {axes}
              <Area
                type="monotone" dataKey={series[0].key} stroke={series[0].color} strokeWidth={2}
                fill={series[0].color} fillOpacity={0.1} dot={data.length <= 12 ? { r: 3, fill: series[0].color, strokeWidth: 0 } : false} activeDot={dot} isAnimationActive={false}
              />
            </AreaChart>
          ) : (
            <LineChart {...common}>
              {axes}
              {series.map((s) => (
                <Line key={s.key} type="monotone" dataKey={s.key} stroke={s.color} strokeWidth={2} dot={data.length <= 12 ? { r: 3, fill: s.color, strokeWidth: 0 } : false} activeDot={dot} connectNulls isAnimationActive={false} />
              ))}
            </LineChart>
          )}
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/** Single-measure bars. `direction="row"` suits long category names; `colors` assigns a reserved status colour per bar. */
export function BarSeriesChart({
  data, xKey, series, unit, direction = "column", colors, height = 224, labelWidth = 150,
}: {
  data: Row[]; xKey: string; series: Series; unit?: string; direction?: "column" | "row"; colors?: string[]; height?: number; labelWidth?: number;
}) {
  const tip = (
    <Tooltip cursor={{ fill: "var(--color-raised)", opacity: 0.6 }} content={<Tip series={[series]} unit={unit} xType="category" />} />
  );
  const cells = colors ? data.map((_, i) => <Cell key={i} fill={colors[i % colors.length]} />) : null;
  const label = { fill: "var(--color-muted)", fontSize: 11 };

  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        {direction === "column" ? (
          <BarChart data={data} margin={{ top: 18, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid stroke={GRID} vertical={false} />
            <XAxis
              dataKey={xKey} tickLine={false} axisLine={{ stroke: GRID }} interval={0}
              {...(data.length > 14 ? { tick: { ...TICK, fontSize: 11 }, angle: -55, textAnchor: "end" as const, height: 40 } : { tick: TICK })}
            />
            <YAxis tick={TICK} tickLine={false} axisLine={false} width={52} tickFormatter={axisNumber} />
            {tip}
            <Bar dataKey={series.key} fill={series.color} radius={[4, 4, 0, 0]} maxBarSize={24} isAnimationActive={false}>
              {cells}
              {data.length <= 10 ? <LabelList dataKey={series.key} position="top" formatter={(v: unknown) => fmt.two(Number(v))} {...label} /> : null}
            </Bar>
          </BarChart>
        ) : (
          <BarChart data={data} layout="vertical" margin={{ top: 0, right: 48, bottom: 0, left: 0 }}>
            <CartesianGrid stroke={GRID} horizontal={false} />
            <XAxis type="number" tick={TICK} tickLine={false} axisLine={false} tickFormatter={axisNumber} />
            <YAxis type="category" dataKey={xKey} tick={TICK} tickLine={false} axisLine={{ stroke: GRID }} width={labelWidth} interval={0} />
            {tip}
            <Bar dataKey={series.key} fill={series.color} radius={[0, 4, 4, 0]} maxBarSize={20} isAnimationActive={false}>
              {cells}
              <LabelList dataKey={series.key} position="right" formatter={(v: unknown) => fmt.one(Number(v))} {...label} />
            </Bar>
          </BarChart>
        )}
      </ResponsiveContainer>
    </div>
  );
}

/** Card shell: the title states what is plotted, the subtitle the question it answers, and "View data" gives the same numbers as a table. */
export function ChartCard({
  title, question, note, source, table, children, className = "",
}: {
  title: string; question?: string; note?: string; source?: string; children: ReactNode; className?: string;
  table?: { columns: string[]; rows: (string | number | null)[][] };
}) {
  return (
    <section className={`rounded-xl border border-line bg-panel p-5 ${className}`}>
      <h3 className="text-sm font-medium text-ink">{title}</h3>
      {question ? <p className="mt-0.5 text-xs text-muted">{question}</p> : null}
      <div className="mt-4">{children}</div>
      {note ? <p className="mt-3 text-xs text-faint">{note}</p> : null}
      {source ? <p className="mt-1.5 text-xs text-faint">{source}</p> : null}
      {table && table.rows.length > 0 ? (
        <details className="mt-3 text-xs">
          <summary className="cursor-pointer text-muted hover:text-ink">View data</summary>
          <div className="mt-2 max-h-56 overflow-auto rounded-lg border border-line">
            <table className="w-full text-left tabular-nums">
              <thead className="sticky top-0 bg-raised text-muted">
                <tr>
                  {table.columns.map((c) => (
                    <th key={c} className="px-3 py-1.5 font-medium">{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {table.rows.map((row, i) => (
                  <tr key={i}>
                    {row.map((cell, j) => (
                      <td key={j} className="px-3 py-1.5 text-ink">{cell ?? "—"}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      ) : null}
    </section>
  );
}

export function EmptyChart({ message = "No data for these filters." }: { message?: string }) {
  return <div className="flex h-40 items-center justify-center text-sm text-faint">{message}</div>;
}
