# CivicOS

**Intelligence for Better Cities.** Urban intelligence platform, built for Mumbai as a multi-tenant SaaS.

**Real data only.** Every figure in the app comes from a published source and carries the report, table and
page it was read from. CivicOS does not generate, simulate or estimate data.

| Data | Source |
| --- | --- |
| Ward boundaries (24 BMC wards) | DataMeet, Municipal Spatial Data (CC BY-SA 2.5 India) |
| Complaints by ward and issue, 2016 to 2025; closure and days to close | Praja Foundation reports (BMC data via RTI) |
| Waste lifted by ward, 2021 to 2025 | Praja Foundation 2026 report |
| Monthly AQI 2016 to 2025; air-quality days by ward, 2025 | Praja Foundation 2026 report |
| Water supply hours by ward (2024), water quality (2020 to 2024), water balance | Praja Foundation 2025 report |

`data/mumbai/README.md` explains how the dataset was extracted and checked, and its known quirks.

```
apps/web/              Next.js (App Router, TypeScript, Tailwind) -> Vercel
supabase/migrations/   Postgres schema, RLS policies, Mumbai data  -> Supabase
supabase/tests/        Tenant-isolation and data tests (run in CI)
data/mumbai/           Extraction scripts, extracted tables, and model training (ml/)
```

## Setup

### 1. Supabase

1. Create a project at supabase.com.
2. Open **SQL Editor**, paste the whole of `supabase/all_migrations.sql`, and run it once.
   (If you ran an earlier version of the migrations in this project, run `supabase/reset.sql` first.)
3. Copy the project URL, anon key and service-role key from **Project Settings -> API**.

### 2. Web app

```bash
cd apps/web
cp .env.example .env.local     # paste the three values
npm install
npm run dev
```

Open http://localhost:3000 and click **Register a municipality**. Leave **City dataset** on Mumbai: the wards and
all published figures load during registration, and you land on the dashboard as City Administrator.

To load or reload the dataset for an existing workspace:

```sql
select app.load_mumbai_data(id) from public.organizations;
```

### 3. Deploy to Vercel

1. Push this repo to GitHub.
2. Import it in Vercel and set **Root Directory** to `apps/web`.
3. Add the same three environment variables.

## What the app shows

- **Dashboard:** KPIs, complaints per year, issue breakdown, registered against closed, ward comparisons,
  monthly AQI, waste, water, and a prototype City Health Index. Filters: year, ward, complaint issue.
  Each chart has a "View data" table and a source line.
- **City Map:** the 24 wards shaded by any of nine published figures or by model ward group; click a ward for all of them.
- **Analytics:** two models trained on the published figures (details in `data/mumbai/ml/README.md`):
  - *Ward groups:* k-means clustering of the 24 wards on complaints, resolution, water, waste and slum share.
  - *Complaint forecasts for 2026:* for 91 series (wards, issues, city), the best of three simple methods
    by rolling backtest, with an 80% range from the backtest errors. Accuracy against a last-year baseline is shown.

Where a figure is not published for the selected year or ward, the app says so and leaves it blank.

## City Health Index

A prototype composite for demonstration, not an official rating. Per ward, for 2025:

| Component | Weight | How it is scored (0 to 100) |
| --- | --- | --- |
| Complaints closed | 25% | closed / registered |
| Speed of resolution | 15% | 100 at 0 days to close, 0 at 60 days or more |
| Hours of water supply | 25% | average hours per day / 24 |
| Drinking-water quality | 15% | 100 minus 20 points per 1% of samples unfit |
| Good-air days | 20% | share of monitored days rated Good or Satisfactory |

A component with no published figure for a ward is left out and the other weights are scaled up. Weights are
per organization in `health_index_config`. The scoring rules are this project's own choices.

## Tenant isolation

Every table in `public` has Row Level Security on. Policies read `org_id` and `role` from the JWT
(`app_metadata`), which a trigger keeps in sync with `public.users`.

```sql
select app.apply_tenant_policies('public.some_table', '{city_admin,dept_officer}', '{city_admin}');
```

Run the tests against any plain Postgres 16:

```bash
createdb civicos_test
DATABASE_URL=postgresql://localhost/civicos_test supabase/tests/run_rls_test.sh shim
```

They check, as every role, that no other tenant's row is visible, that cross-tenant and privilege-escalating
writes fail, that no table has RLS off, and that the dashboard returns the figures printed in the reports.
`shim` mode stores geometry as GeoJSON text so it runs without PostGIS; it is for tests only.

## Map basemap

CARTO's dark raster tiles over OpenStreetMap data by default, with attribution on the map.
Set `NEXT_PUBLIC_MAP_STYLE_URL` to use another MapLibre style.

## Not built yet

- Citizen complaint submission and the complaint workflow (the tables exist and stay empty until real users submit).
- Traffic: no published ward-level traffic data was found; live traffic needs an API key and builds history from the day collection starts.
- Water-leak and bin-overflow models (no Mumbai sensor data is published), the document assistant,
  recommendations, invitations, billing, exports.
- When a user's role changes, their JWT picks it up at the next token refresh (up to an hour) or next sign-in.
