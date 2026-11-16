import { DIVERGING, GROUP_COLORS } from "@/lib/chart-colors";
import { fmt } from "@/lib/dashboard";
import type { Feature, Group } from "@/lib/models";

/**
 * How each group differs from the city average, feature by feature, in standard deviations.
 * Bars run right of the centre line when the group is above average. Colour says whether that is
 * better (blue) or worse (red) for residents; grey where higher is neither better nor worse.
 */
export function GroupProfile({ groups, features, cityMean }: { groups: Group[]; features: Feature[]; cityMean: Record<string, number> }) {
  const limit = Math.max(1, ...groups.flatMap((g) => features.map((f) => Math.abs(g.z[f.key] ?? 0))));

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-xs">
        <thead className="text-muted">
          <tr>
            <th className="py-2 pr-3 font-medium">Indicator</th>
            <th className="py-2 pr-3 text-right font-medium">City average</th>
            {groups.map((g) => (
              <th key={g.cluster} className="py-2 pr-3 font-medium">
                <span className="inline-flex items-center gap-1.5 text-ink">
                  <span className="inline-block size-2.5 rounded-sm" style={{ background: GROUP_COLORS[g.cluster - 1] }} />
                  Group {g.cluster}
                </span>
                <span className="block font-normal text-faint">{g.wards.length} wards</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {features.map((f) => (
            <tr key={f.key}>
              <td className="py-2 pr-3 text-ink">{f.label}</td>
              <td className="py-2 pr-3 text-right tabular-nums text-muted">{fmt.two(cityMean[f.key])}</td>
              {groups.map((g) => {
                const z = g.z[f.key] ?? 0;
                const better = f.higher_is_better == null ? null : f.higher_is_better ? z > 0 : z < 0;
                const color = better == null ? "var(--color-faint)" : better ? DIVERGING.pos : DIVERGING.neg;
                const w = (Math.abs(z) / limit) * 50;
                return (
                  <td key={g.cluster} className="py-2 pr-3">
                    <div className="flex items-center gap-2">
                      <span className="relative h-3 w-28 shrink-0 rounded-sm bg-raised" title={`${z > 0 ? "+" : ""}${z.toFixed(2)} standard deviations from the city average`}>
                        <span className="absolute inset-y-0 left-1/2 w-px bg-faint" />
                        <span className="absolute inset-y-0 rounded-sm" style={{ background: color, width: `${w}%`, left: z >= 0 ? "50%" : `${50 - w}%` }} />
                      </span>
                      <span className="tabular-nums text-ink">{fmt.two(g.mean[f.key])}</span>
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
        <span>Bar = distance from the city average (centre line).</span>
        <span className="inline-flex items-center gap-1.5"><span className="inline-block size-2.5 rounded-sm" style={{ background: DIVERGING.pos }} />Better than average</span>
        <span className="inline-flex items-center gap-1.5"><span className="inline-block size-2.5 rounded-sm" style={{ background: DIVERGING.neg }} />Worse than average</span>
        <span className="inline-flex items-center gap-1.5"><span className="inline-block size-2.5 rounded-sm bg-faint" />Neither</span>
      </p>
    </div>
  );
}
