export type Filters = {
  year: number | null; // null = latest published year
  zone: string | null; // ward id
  issue: string | null; // complaint issue name; null = all issues
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
type Params = Record<string, string | string[] | undefined>;
const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

/** Reads filters from the URL. Malformed values fall back to "all", so the SQL only sees clean input. */
export function parseFilters(params: Params): Filters {
  const year = Number(one(params.year));
  const zone = one(params.zone);
  const issue = one(params.issue);
  return {
    year: Number.isInteger(year) && year >= 2000 && year <= 2100 ? year : null,
    zone: zone && UUID.test(zone) ? zone : null,
    issue: issue && issue.length <= 80 ? issue : null,
  };
}
