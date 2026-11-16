"use client";

import "maplibre-gl/dist/maplibre-gl.css";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ExpressionSpecification, GeoJSONSource, LngLatBoundsLike, Map as MlMap, StyleSpecification } from "maplibre-gl";
import { Search } from "lucide-react";
import type { Ward } from "@/lib/dashboard";
import { GROUP_COLORS } from "@/lib/chart-colors";
import type { Group } from "@/lib/models";

type FC = GeoJSON.FeatureCollection<GeoJSON.Geometry, Ward>;
export type MapData = { year: number; years: number[]; ward_issues: string[] | null; groups: Group[] | null; zones: FC };

type MetricKey = "per_10k" | "closed_pct" | "avg_days" | "waste_tpd" | "waste_per_capita" | "water_hours" | "water_unfit_pct" | "air_good_days" | "health_score" | "ward_group";
type Metric = { key: MetricKey; group: string; label: string; unit: string; yearOf?: (w: Ward) => number | null; fixedYear?: number };

/** Every layer is a ward-level figure from a published table. There are no point layers because no real point data exists yet. */
const METRICS: Metric[] = [
  { key: "per_10k", group: "Complaints", label: "Complaints per 10,000 residents", unit: "" },
  { key: "closed_pct", group: "Complaints", label: "Complaints closed", unit: "%" },
  { key: "avg_days", group: "Complaints", label: "Average days to close", unit: "days" },
  { key: "waste_tpd", group: "Waste", label: "Waste lifted", unit: "t/day" },
  { key: "waste_per_capita", group: "Waste", label: "Waste per person", unit: "kg/day", fixedYear: 2025 },
  { key: "water_hours", group: "Water", label: "Water supply", unit: "hrs/day", yearOf: (w) => w.water_hours_year },
  { key: "water_unfit_pct", group: "Water", label: "Water samples found unfit", unit: "%", yearOf: (w) => w.water_unfit_year },
  { key: "air_good_days", group: "Environment", label: "Good or satisfactory air days", unit: "days", yearOf: (w) => w.air_year },
  { key: "health_score", group: "Index", label: "Health score (prototype)", unit: "/ 100", fixedYear: 2025 },
  { key: "ward_group", group: "Model", label: "Ward group (clustering)", unit: "", fixedYear: 2025 },
];

// One blue ramp for magnitude; on the dark basemap a brighter ward means a higher value.
const RAMP = { low: "#0d366b", mid: "#2a78d6", high: "#cde2fb", none: "#2a3348" };

const DEFAULT_STYLE: StyleSpecification = {
  version: 8,
  sources: {
    basemap: {
      type: "raster",
      tiles: ["a", "b", "c", "d"].map((s) => `https://${s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}@2x.png`),
      tileSize: 256,
      attribution:
        '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors © <a href="https://carto.com/attributions">CARTO</a> · Ward boundaries: <a href="https://github.com/datameet/Municipal_Spatial_Data">DataMeet</a> (CC BY-SA 2.5 IN)',
    },
  },
  layers: [{ id: "basemap", type: "raster", source: "basemap" }],
};

const esc = (v: unknown) =>
  String(v ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
const n = (v: unknown, digits = 0) =>
  v == null || v === "" || v === "null" ? "not published" : Number(v).toLocaleString("en-IN", { maximumFractionDigits: digits });
const row = (label: string, value: string) => `<div><span style="color:#8c9ab5">${esc(label)}:</span> ${esc(value)}</div>`;

function popupHtml(p: Record<string, unknown>, year: number, issue: string | null): string {
  return (
    `<div style="font-weight:600;margin-bottom:4px">${esc(p.name)}</div>` +
    row("Population (2025)", n(p.population)) +
    row(`Complaints ${year}${issue ? `, ${issue}` : ""}`, n(p.registered)) +
    row("Per 10,000 residents", n(p.per_10k, 1)) +
    row("Closed", p.closed_pct == null || p.closed_pct === "null" ? "not published" : `${n(p.closed_pct, 1)}%`) +
    row("Average days to close", n(p.avg_days)) +
    row(`Waste lifted ${year}`, p.waste_tpd == null || p.waste_tpd === "null" ? "not published" : `${n(p.waste_tpd)} t/day`) +
    row(`Water supply (${p.water_hours_year ?? "—"})`, `${n(p.water_hours, 2)} hrs/day`) +
    row(`Unfit water samples (${p.water_unfit_year ?? "—"})`, `${n(p.water_unfit_pct, 2)}%`) +
    row("Good or satisfactory air days (2025)", p.air_good_days == null || p.air_good_days === "null" ? "no station" : n(p.air_good_days)) +
    row("Health score (prototype)", n(p.health_score, 1)) +
    row("Ward group", p.ward_group == null || p.ward_group === "null" ? "—" : `Group ${p.ward_group}`)
  );
}

function bounds(fc: GeoJSON.FeatureCollection): [[number, number], [number, number]] | null {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  const visit = (c: unknown): void => {
    if (Array.isArray(c) && typeof c[0] === "number") {
      x0 = Math.min(x0, c[0]); x1 = Math.max(x1, c[0]); y0 = Math.min(y0, c[1] as number); y1 = Math.max(y1, c[1] as number);
    } else if (Array.isArray(c)) c.forEach(visit);
  };
  fc.features.forEach((f) => f.geometry && "coordinates" in f.geometry && visit(f.geometry.coordinates));
  return Number.isFinite(x0) ? [[x0, y0], [x1, y1]] : null;
}

export function CityMap({ data, issue }: { data: MapData; issue: string | null }) {
  const container = useRef<HTMLDivElement>(null);
  const mapRef = useRef<MlMap | null>(null);
  const yearRef = useRef(data.year);
  const issueRef = useRef(issue);
  const [ready, setReady] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const [tilesFailed, setTilesFailed] = useState(false);
  const [metricKey, setMetricKey] = useState<MetricKey>("per_10k");
  const [query, setQuery] = useState("");
  const [searchNote, setSearchNote] = useState<string | null>(null);

  const metric = METRICS.find((m) => m.key === metricKey)!;
  const wards = useMemo(() => data.zones.features.map((f) => f.properties), [data.zones]);
  const values = useMemo(() => wards.map((w) => w[metricKey]).filter((v): v is number => v != null), [wards, metricKey]);
  const lo = values.length ? Math.min(...values) : 0;
  const hi = values.length ? Math.max(...values) : 1;
  const missing = wards.length - values.length;
  const metricYear = metric.fixedYear ?? (metric.yearOf ? wards.map(metric.yearOf).find((y) => y != null) ?? null : data.year);
  const ranked = useMemo(
    () => wards.filter((w) => w[metricKey] != null).sort((a, b) => (b[metricKey] as number) - (a[metricKey] as number)),
    [wards, metricKey],
  );

  useEffect(() => {
    yearRef.current = data.year;
    issueRef.current = issue;
  }, [data.year, issue]);

  // ---- create the map once -------------------------------------------------
  useEffect(() => {
    let cancelled = false;
    let map: MlMap | null = null;

    (async () => {
      const ml = await import("maplibre-gl");
      if (cancelled || !container.current) return;

      const fit = bounds(data.zones);
      map = new ml.Map({
        container: container.current,
        style: process.env.NEXT_PUBLIC_MAP_STYLE_URL || DEFAULT_STYLE,
        bounds: (fit as LngLatBoundsLike) ?? undefined,
        fitBoundsOptions: { padding: 30 },
        center: fit ? undefined : [72.88, 19.08],
        zoom: fit ? undefined : 10,
        attributionControl: { compact: true },
      });
      mapRef.current = map;
      map.addControl(new ml.NavigationControl({ showCompass: false }), "top-right");
      map.addControl(new ml.ScaleControl({ unit: "metric" }), "bottom-right");
      map.on("error", (e) => {
        // A failed basemap tile is not fatal: the ward layer still draws. Anything else is.
        if ("sourceId" in e || "tile" in e) setTilesFailed(true);
        else setFailed(e.error?.message ?? "The map could not load.");
      });

      map.on("load", () => {
        if (!map) return;
        map.addSource("zones", { type: "geojson", data: data.zones });
        map.addLayer({ id: "zones-fill", type: "fill", source: "zones", paint: { "fill-color": RAMP.none, "fill-opacity": 0.72 } });
        map.addLayer({ id: "zones-line", type: "line", source: "zones", paint: { "line-color": "#0a101c", "line-width": 1.5 } });

        // ward codes as HTML labels (a raster basemap has no font glyphs for a symbol layer)
        for (const f of data.zones.features) {
          const b = bounds({ type: "FeatureCollection", features: [f] });
          if (!b) continue;
          const el = document.createElement("div");
          el.textContent = f.properties.code;
          el.style.cssText = "font:600 11px var(--font-sans);color:#e7ecf5;text-shadow:0 0 3px #0a101c,0 0 3px #0a101c;pointer-events:none";
          new ml.Marker({ element: el }).setLngLat([(b[0][0] + b[1][0]) / 2, (b[0][1] + b[1][1]) / 2]).addTo(map);
        }

        map.on("click", "zones-fill", (e) => {
          const hit = e.features?.[0];
          if (!hit) return;
          new ml.Popup({ maxWidth: "300px" }).setLngLat(e.lngLat).setHTML(popupHtml(hit.properties ?? {}, yearRef.current, issueRef.current)).addTo(map!);
        });
        map.on("mouseenter", "zones-fill", () => (map!.getCanvas().style.cursor = "pointer"));
        map.on("mouseleave", "zones-fill", () => (map!.getCanvas().style.cursor = ""));
        setReady(true);
      });
    })().catch((err: unknown) => setFailed(err instanceof Error ? err.message : "The map could not load."));

    return () => {
      cancelled = true;
      map?.remove();
      mapRef.current = null;
    };
    // The map is created once; later data changes are pushed in the effects below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---- new data (year or issue changed) ------------------------------------
  useEffect(() => {
    const map = mapRef.current;
    if (!ready || !map) return;
    (map.getSource("zones") as GeoJSONSource | undefined)?.setData(data.zones);
  }, [data.zones, ready]);

  // ---- shading -------------------------------------------------------------
  useEffect(() => {
    const map = mapRef.current;
    if (!ready || !map) return;
    if (metricKey === "ward_group") {
      const match: ExpressionSpecification = ["match", ["get", "ward_group"], 1, GROUP_COLORS[0], 2, GROUP_COLORS[1], 3, GROUP_COLORS[2], RAMP.none];
      map.setPaintProperty("zones-fill", "fill-color", match);
      return;
    }
    const top = hi === lo ? lo + 1 : hi;
    const color: ExpressionSpecification = [
      "case",
      ["==", ["typeof", ["get", metricKey]], "number"],
      ["interpolate", ["linear"], ["get", metricKey], lo, RAMP.low, (lo + top) / 2, RAMP.mid, top, RAMP.high],
      RAMP.none,
    ];
    map.setPaintProperty("zones-fill", "fill-color", color);
  }, [metricKey, lo, hi, ready, data.zones]);

  function search(e: React.FormEvent) {
    e.preventDefault();
    const map = mapRef.current;
    const q = query.trim().toLowerCase().replace(/^ward\s+/, "");
    if (!map || !q) return;
    const zone = data.zones.features.find((f) => f.properties.code.toLowerCase() === q);
    const b = zone ? bounds({ type: "FeatureCollection", features: [zone] }) : null;
    if (b) {
      map.fitBounds(b, { padding: 80, duration: 600 });
      setSearchNote(null);
    } else {
      setSearchNote("No ward matches. Try a ward code such as “K/W” or “M/E”.");
    }
  }

  const groups = [...new Set(METRICS.map((m) => m.group))];

  return (
    <div className="grid gap-4 lg:grid-cols-[280px_1fr]">
      <aside className="space-y-4 rounded-xl border border-line bg-panel p-4 text-sm">
        <form onSubmit={search}>
          <label className="mb-1.5 block text-xs font-medium text-muted" htmlFor="map-search">Find a ward</label>
          <div className="flex gap-2">
            <input
              id="map-search" list="ward-codes" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Ward code, e.g. K/W"
              className="h-9 min-w-0 flex-1 rounded-lg border border-line bg-raised px-2.5 text-sm placeholder:text-faint focus:border-accent focus:outline-none"
            />
            <button type="submit" aria-label="Search" className="inline-flex size-9 items-center justify-center rounded-lg border border-line bg-raised text-muted hover:text-ink">
              <Search className="size-4" aria-hidden="true" />
            </button>
          </div>
          <datalist id="ward-codes">
            {wards.map((w) => <option key={w.code} value={w.code} />)}
          </datalist>
          {searchNote ? <p role="status" className="mt-2 text-xs text-warn">{searchNote}</p> : null}
        </form>

        <fieldset>
          <legend className="mb-2 text-xs font-medium text-muted">Shade wards by</legend>
          {groups.map((g) => (
            <div key={g} className="mb-2.5">
              <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-faint">{g}</p>
              <ul className="space-y-1">
                {METRICS.filter((m) => m.group === g).map((m) => (
                  <li key={m.key}>
                    <label className="flex cursor-pointer items-center gap-2.5">
                      <input type="radio" name="metric" className="size-4 accent-[#3ecfb2]" checked={metricKey === m.key} onChange={() => setMetricKey(m.key)} />
                      {m.label}
                    </label>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </fieldset>

        <div>
          <p className="text-xs font-medium text-ink">
            {metric.label}
            {metric.unit ? `, ${metric.unit}` : ""}
            {metricYear ? ` · ${metricYear}` : ""}
          </p>
          {metricKey === "ward_group" && data.groups ? (
            <ul className="mt-2 space-y-1.5 text-xs">
              {[...data.groups].sort((a, b) => a.cluster - b.cluster).map((g) => (
                <li key={g.cluster} className="flex items-start gap-2">
                  <span className="mt-0.5 inline-block size-3 shrink-0 rounded-sm" style={{ background: GROUP_COLORS[g.cluster - 1] }} />
                  <span><span className="text-ink">Group {g.cluster}</span> <span className="text-muted">· {g.label} · {g.wards.length} wards</span></span>
                </li>
              ))}
            </ul>
          ) : values.length ? (
            <>
              <div className="mt-2 h-2 rounded" style={{ background: `linear-gradient(to right, ${RAMP.low}, ${RAMP.mid}, ${RAMP.high})` }} />
              <div className="mt-1 flex justify-between text-xs tabular-nums text-muted">
                <span>{n(lo, 2)}</span>
                <span>{n(hi, 2)}</span>
              </div>
            </>
          ) : (
            <p className="mt-2 text-xs text-warn">Not published for {data.year}{issue ? ` and ${issue}` : ""}.</p>
          )}
          {missing > 0 && values.length ? (
            <p className="mt-2 flex items-center gap-1.5 text-xs text-muted">
              <span className="inline-block size-3 rounded-sm" style={{ background: RAMP.none }} />
              {missing} {missing === 1 ? "ward" : "wards"} with no published figure
            </p>
          ) : null}
        </div>

        {ranked.length && metricKey !== "ward_group" ? (
          <div className="grid grid-cols-2 gap-3 border-t border-line pt-3 text-xs">
            <div>
              <p className="mb-1 font-medium text-muted">Highest</p>
              {ranked.slice(0, 3).map((w) => (
                <p key={w.code} className="flex justify-between tabular-nums"><span>{w.code}</span><span className="text-muted">{n(w[metricKey], 2)}</span></p>
              ))}
            </div>
            <div>
              <p className="mb-1 font-medium text-muted">Lowest</p>
              {ranked.slice(-3).reverse().map((w) => (
                <p key={w.code} className="flex justify-between tabular-nums"><span>{w.code}</span><span className="text-muted">{n(w[metricKey], 2)}</span></p>
              ))}
            </div>
          </div>
        ) : null}

        <p className="border-t border-line pt-3 text-xs leading-relaxed text-faint">
          Ward figures are from Praja Foundation&apos;s reports on BMC data. Individual complaints, bins and meters are not shown because no real location data for them is published.
        </p>
      </aside>

      <div className="relative h-[calc(100vh-15rem)] min-h-[560px] overflow-hidden rounded-xl border border-line bg-panel">
        <div ref={container} className="h-full w-full" role="application" aria-label="Ward map" />
        {!ready && !failed ? <p className="absolute inset-0 flex items-center justify-center text-sm text-muted">Loading map…</p> : null}
        {tilesFailed && !failed ? (
          <p className="absolute left-3 top-3 rounded-md border border-line bg-base/85 px-2.5 py-1.5 text-xs text-muted">
            Some basemap tiles did not load. Ward data is still shown.
          </p>
        ) : null}
        {failed ? (
          <p className="absolute inset-x-6 top-6 rounded-lg border border-danger/40 bg-base/90 p-3 text-sm text-danger">Map failed to load: {failed}</p>
        ) : null}
      </div>
    </div>
  );
}
