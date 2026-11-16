import type { LucideIcon } from "lucide-react";
import { COMPONENT_HOW, COMPONENT_LABEL, fmt, MONTHS, type DashboardData } from "@/lib/dashboard";

export function KpiCard({
  icon: Icon, label, value, unit, note,
}: { icon: LucideIcon; label: string; value: string; unit?: string; note?: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel p-4">
      <div className="flex items-center gap-2 text-xs font-medium text-muted">
        <Icon className="size-4 shrink-0 text-accent" aria-hidden="true" />
        {label}
      </div>
      <p className="mt-2.5 text-[28px] font-semibold leading-none tracking-tight tabular-nums">
        {value}
        {unit && value !== "—" ? <span className="ml-1 text-sm font-normal text-muted">{unit}</span> : null}
      </p>
      <p className="mt-2 min-h-4 text-xs text-faint">{note}</p>
    </div>
  );
}

/** Registered against closed. The reports publish only these two stages, so the funnel has two bars and the gap is what is still open. */
export function Funnel({ registered, closed }: { registered: number; closed: number }) {
  const stages = [
    { stage: "Registered", count: registered },
    { stage: "Closed", count: closed },
  ];
  return (
    <div>
      <ol className="space-y-2">
        {stages.map((s) => {
          const pct = (100 * s.count) / registered;
          return (
            <li key={s.stage} className="grid grid-cols-[84px_1fr_112px] items-center gap-3 text-xs">
              <span className="text-muted">{s.stage}</span>
              <span className="h-6 rounded-r bg-raised">
                <span className="block h-6 rounded-r bg-series-1" style={{ width: `${Math.max(pct, 0.5)}%` }} title={`${s.stage}: ${fmt.int(s.count)}`} />
              </span>
              <span className="text-right tabular-nums text-ink">
                {fmt.int(s.count)} <span className="text-faint">· {pct.toFixed(0)}%</span>
              </span>
            </li>
          );
        })}
      </ol>
      <p className="mt-4 text-sm text-muted">
        <span className="font-medium tabular-nums text-ink">{fmt.int(registered - closed)}</span> complaints registered in the year were not closed.
      </p>
    </div>
  );
}

function scoreTone(score: number) {
  if (score >= 80) return { label: "Good", cls: "text-status-good" };
  if (score >= 65) return { label: "Fair", cls: "text-status-warning" };
  if (score >= 50) return { label: "Strained", cls: "text-status-serious" };
  return { label: "Poor", cls: "text-status-critical" };
}

/** City Health Index: the score and the weighted components behind it, strongest and weakest called out. */
export function HealthIndex({ health }: { health: DashboardData["health"] }) {
  if (health.score == null || !health.components) {
    return <p className="py-10 text-center text-sm text-faint">No health index has been computed.</p>;
  }
  const tone = scoreTone(health.score);
  const keys = Object.keys(COMPONENT_LABEL).filter((k) => health.components![k] != null);
  const ranked = [...keys].sort((a, b) => health.components![b] - health.components![a]);
  const raising = ranked.filter((k) => health.components![k] > health.score!);
  const lowering = ranked.filter((k) => health.components![k] < health.score!).reverse();

  return (
    <div className="grid gap-6 lg:grid-cols-[180px_1fr_260px]">
      <div>
        <p className="text-6xl font-semibold leading-none tracking-tight tabular-nums">{fmt.one(health.score)}</p>
        <p className="mt-2 text-sm text-muted">
          out of 100 · <span className={tone.cls}>●</span> {tone.label}
        </p>
        <p className="mt-3 text-xs text-faint">Computed for {health.year}</p>
      </div>

      <div>
        <p className="mb-3 text-xs font-medium text-muted">Component scores and weights</p>
        <ul className="space-y-3">
          {keys.map((k) => (
            <li key={k}>
              <div className="grid grid-cols-[150px_1fr_78px] items-center gap-3 text-xs">
                <span className="text-ink">{COMPONENT_LABEL[k]}</span>
                <span className="h-2 rounded-full bg-raised">
                  <span className="block h-2 rounded-full bg-series-1" style={{ width: `${health.components![k]}%` }} />
                </span>
                <span className="text-right tabular-nums text-ink">
                  {fmt.one(health.components![k])}
                  <span className="text-faint"> · {Math.round((health.weights?.[k] ?? 0) * 100)}%</span>
                </span>
              </div>
              <p className="mt-0.5 text-[11px] text-faint">{COMPONENT_HOW[k]}</p>
            </li>
          ))}
        </ul>
      </div>

      <div className="space-y-4 text-xs">
        <div>
          <p className="mb-1.5 font-medium text-muted">Raising the score</p>
          <p className="text-ink">{raising.length ? raising.map((k) => COMPONENT_LABEL[k]).join(", ") : "No component is above the overall score."}</p>
        </div>
        <div>
          <p className="mb-1.5 font-medium text-muted">Lowering the score</p>
          <p className="text-ink">{lowering.length ? lowering.map((k) => COMPONENT_LABEL[k]).join(", ") : "No component is below the overall score."}</p>
        </div>
        <p className="text-faint">
          One year is computed so far, because closure and air-quality figures by ward are not published for earlier years in the same form. A history needs more annual reports.
        </p>
      </div>
    </div>
  );
}

const RAMP_LOW = [13, 54, 107]; // #0d366b
const RAMP_HIGH = [205, 226, 251]; // #cde2fb

/** Month by year grid of average AQI. One hue: a brighter cell means a higher AQI, i.e. worse air. Every cell prints its value. */
export function AqiGrid({ grid }: { grid: DashboardData["aqi"]["grid"] }) {
  const all = grid.flatMap((r) => r.values);
  const lo = Math.min(...all);
  const hi = Math.max(...all);
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[440px] table-fixed border-separate border-spacing-[2px] text-center text-[11px] tabular-nums">
        <thead>
          <tr className="text-muted">
            <th className="w-10 py-1 text-left font-medium">Year</th>
            {MONTHS.map((m) => (
              <th key={m} className="py-1 font-medium">{m}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {grid.map((row) => (
            <tr key={row.year}>
              <th className="py-1 text-left font-medium text-muted">{row.year}</th>
              {row.values.map((v, i) => {
                const t = hi === lo ? 0.5 : (v - lo) / (hi - lo);
                const rgb = RAMP_LOW.map((c, j) => Math.round(c + t * (RAMP_HIGH[j] - c)));
                return (
                  <td
                    key={i}
                    title={`${MONTHS[i]} ${row.year}: average AQI ${v}`}
                    className="rounded py-1.5"
                    style={{ background: `rgb(${rgb.join(",")})`, color: t > 0.55 ? "#0a101c" : "#e7ecf5" }}
                  >
                    {v}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mt-2 flex items-center gap-2 text-xs text-muted">
        <span className="tabular-nums">{lo}</span>
        <span className="h-2 w-40 rounded" style={{ background: "linear-gradient(to right, #0d366b, #2a78d6, #cde2fb)" }} />
        <span className="tabular-nums">{hi}</span>
        <span className="ml-1">Brighter = higher AQI = worse air</span>
      </div>
    </div>
  );
}

export function Stat({ label, value, unit }: { label: string; value: string; unit?: string }) {
  return (
    <div className="rounded-lg border border-line px-3 py-2.5">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-1 text-lg font-semibold tabular-nums">
        {value}
        {unit ? <span className="ml-1 text-xs font-normal text-muted">{unit}</span> : null}
      </p>
    </div>
  );
}
