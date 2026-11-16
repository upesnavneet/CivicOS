import type { Metadata } from "next";
import { FilterBar } from "@/components/filter-bar";
import { CityMap, type MapData } from "@/components/map/city-map";
import { requireSession } from "@/lib/auth";
import { parseFilters } from "@/lib/filters";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = { title: "City Map" };

export default async function MapPage({ searchParams }: PageProps<"/map">) {
  await requireSession();
  const filters = parseFilters(await searchParams);
  const supabase = await createClient();

  const [{ data, error }, city] = await Promise.all([
    supabase.rpc("map_data", { p_year: filters.year, p_issue: filters.issue }),
    supabase.from("cities").select("name").limit(1).maybeSingle(),
  ]);
  const d = data as MapData | null;
  const cityName = city.data?.name ?? "City";

  return (
    <div className="mx-auto max-w-[1400px] space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">City Map</h1>
        <p className="mt-1 text-sm text-muted">
          {cityName} by ward{d?.year ? ` · ${d.year}` : ""} · click a ward for its figures
        </p>
      </div>

      {error || !d ? (
        <div className="rounded-xl border border-line bg-panel p-6 text-sm text-muted">
          The map query failed: {error?.message ?? "no data returned"}. Check that every migration in supabase/migrations has been run.
        </div>
      ) : d.zones.features.length === 0 ? (
        <div className="rounded-xl border border-line bg-panel p-6 text-sm text-muted">
          This workspace has no ward boundaries yet. Load a city dataset from the dashboard.
        </div>
      ) : (
        <>
          <FilterBar filters={filters} city={cityName} year={d.year} years={d.years ?? []} issues={d.ward_issues ?? []} />
          <CityMap data={d} issue={filters.issue} />
        </>
      )}
    </div>
  );
}
