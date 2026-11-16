"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useTransition } from "react";

const selectCls = "h-9 rounded-lg border border-line bg-raised px-2.5 text-sm text-ink focus:border-accent focus:outline-none";

/** Picks which complaint series to forecast. Ward-level forecasts exist only for the issues the reports break down by ward. */
export function SeriesPicker({
  zone, issue, wards, cityIssues, wardIssues,
}: { zone: string | null; issue: string | null; wards: { id: string; name: string }[]; cityIssues: string[]; wardIssues: string[] }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [pending, startTransition] = useTransition();
  const issues = zone ? wardIssues : cityIssues;

  function update(changes: Record<string, string | null>) {
    const next = new URLSearchParams(params.toString());
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    startTransition(() => router.replace(`${pathname}?${next.toString()}`, { scroll: false }));
  }

  return (
    <div className={`flex flex-wrap items-end gap-3 ${pending ? "opacity-60" : ""}`} aria-busy={pending}>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Ward
        <select
          className={selectCls}
          value={zone ?? ""}
          onChange={(e) => update({ zone: e.target.value || null, issue: e.target.value && issue && !wardIssues.includes(issue) ? null : issue })}
        >
          <option value="">Whole city</option>
          {wards.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Complaint issue
        <select className={selectCls} value={issue ?? ""} onChange={(e) => update({ issue: e.target.value || null })}>
          <option value="">All issues</option>
          {issues.map((i) => <option key={i} value={i}>{i}</option>)}
        </select>
      </label>
    </div>
  );
}
