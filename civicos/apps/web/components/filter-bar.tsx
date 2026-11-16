"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useTransition } from "react";
import { RotateCcw } from "lucide-react";
import type { Option } from "@/lib/dashboard";
import type { Filters } from "@/lib/filters";

type Props = {
  filters: Filters;
  city: string;
  year: number;
  years: number[];
  zones?: Option[];
  issues: string[];
};

const selectCls =
  "h-9 rounded-lg border border-line bg-raised px-2.5 text-sm text-ink focus:border-accent focus:outline-none disabled:opacity-60";

/** One row of filters above the charts. State lives in the URL, so a filtered view can be shared or bookmarked. */
export function FilterBar({ filters, city, year, years, zones, issues }: Props) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [pending, startTransition] = useTransition();

  function update(key: string, value: string) {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(key, value);
    else next.delete(key);
    startTransition(() => router.replace(`${pathname}?${next.toString()}`, { scroll: false }));
  }

  const active = filters.year || filters.zone || filters.issue;

  return (
    <div className={`flex flex-wrap items-end gap-3 rounded-xl border border-line bg-panel p-3 transition-opacity ${pending ? "opacity-60" : ""}`} aria-busy={pending}>
      <label className="flex flex-col gap-1 text-xs text-muted">
        City
        <select className={selectCls} disabled value={city}>
          <option>{city}</option>
        </select>
      </label>

      <label className="flex flex-col gap-1 text-xs text-muted">
        Year
        <select className={selectCls} value={year} onChange={(e) => update("year", e.target.value)}>
          {[...years].reverse().map((y) => (
            <option key={y} value={y}>
              {y}
            </option>
          ))}
        </select>
      </label>

      {zones ? (
        <label className="flex flex-col gap-1 text-xs text-muted">
          Ward
          <select className={selectCls} value={filters.zone ?? ""} onChange={(e) => update("zone", e.target.value)}>
            <option value="">All wards</option>
            {zones.map((z) => (
              <option key={z.id} value={z.id}>
                {z.name}
              </option>
            ))}
          </select>
        </label>
      ) : null}

      <label className="flex flex-col gap-1 text-xs text-muted">
        Complaint issue
        <select className={selectCls} value={filters.issue ?? ""} onChange={(e) => update("issue", e.target.value)}>
          <option value="">All issues</option>
          {issues.map((i) => (
            <option key={i} value={i}>
              {i}
            </option>
          ))}
        </select>
      </label>

      {active ? (
        <button
          type="button"
          onClick={() => startTransition(() => router.replace(pathname, { scroll: false }))}
          className="ml-auto inline-flex h-9 items-center gap-1.5 rounded-lg px-2.5 text-sm text-muted hover:text-ink"
        >
          <RotateCcw className="size-3.5" aria-hidden="true" />
          Reset
        </button>
      ) : null}
    </div>
  );
}
