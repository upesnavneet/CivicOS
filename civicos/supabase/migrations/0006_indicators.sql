-- CivicOS 0006: published civic statistics.
-- One long table holds every figure taken from a published report, each row
-- pointing at the report, table and page it came from. Nothing in here is
-- generated or estimated by CivicOS.

create table public.data_sources (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  id              text not null,                 -- e.g. 'p26-t43'
  publisher       text not null,
  report          text not null,
  table_ref       text,                          -- 'Table 43'
  page            int,                           -- PDF page
  title           text not null,
  url             text,
  note            text,
  primary key (organization_id, id)
);

create table public.civic_indicators (
  id              bigint generated always as identity primary key,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  zone_id         uuid references public.city_zones(id) on delete cascade,   -- null = whole city
  year            int  not null,
  month           int  check (month between 1 and 12),                        -- null = whole year
  metric          text not null,                 -- complaints_registered, waste_tonnes_per_day, ...
  category        text,                          -- issue name, air-quality level, hours band; null = all
  value           numeric not null,
  unit            text not null,
  source_id       text not null,
  foreign key (organization_id, source_id) references public.data_sources (organization_id, id) on delete cascade
);
create unique index civic_indicators_key on public.civic_indicators
  (organization_id, coalesce(zone_id, '00000000-0000-0000-0000-000000000000'::uuid),
   year, coalesce(month, 0), metric, coalesce(category, ''));
create index civic_indicators_metric_idx on public.civic_indicators (organization_id, metric, year);

create table public.health_index_config (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  weights         jsonb not null default
    '{"complaint_closure": 0.25, "resolution_speed": 0.15, "water_supply": 0.25, "water_quality": 0.15, "air_quality": 0.20}',
  updated_at      timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Grants and RLS (repeated because the tables above are new)
-- ---------------------------------------------------------------------------
grant select, insert, update, delete on all tables in schema public to authenticated;
grant all on all tables in schema public to service_role;
grant usage, select on all sequences in schema public to authenticated, service_role;
revoke all on all tables in schema public from anon;
revoke insert, update, delete on public.plans, public.roles, public.permissions, public.role_permissions,
  public.audit_logs, public.data_sources, public.civic_indicators from authenticated;
revoke update, delete on public.usage_records from authenticated;
revoke update on public.organizations from authenticated;
grant update (name) on public.organizations to authenticated;

-- Published statistics are readable by every member of the organization, written by nobody.
select app.apply_tenant_policies('public.data_sources',
  '{city_admin,dept_officer,field_worker,citizen}', '{}');
select app.apply_tenant_policies('public.civic_indicators',
  '{city_admin,dept_officer,field_worker,citizen}', '{}');
select app.apply_tenant_policies('public.health_index_config', '{city_admin,dept_officer}', '{city_admin}');

-- ---------------------------------------------------------------------------
-- City Health Index: a PROTOTYPE composite, not an official municipal rating.
-- Built only from published figures, one snapshot per ward for p_year:
--   complaint_closure : complaints closed / registered in p_year, as a percentage
--   resolution_speed  : 100 x (1 - average days to close / 60), floored at 0
--   water_supply      : average supply hours per day / 24, as a percentage  (latest year published)
--   water_quality     : 100 - 20 x (% of drinking-water samples unfit), floored at 0 (latest year published)
--   air_quality       : share of monitored days rated Good or Satisfactory   (wards with a station only)
-- A component with no published figure is left out and the other weights are re-normalised.
-- ---------------------------------------------------------------------------
create or replace function app.compute_health_index(p_org uuid, p_year int) returns int
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_weights jsonb;
  v_rows int;
  v_date date := make_date(p_year, 12, 31);
begin
  insert into health_index_config (organization_id) values (p_org) on conflict do nothing;
  select weights into v_weights from health_index_config where organization_id = p_org;
  delete from health_index_snapshots where organization_id = p_org and snapshot_date = v_date;

  with latest as (   -- newest published year per metric, not after p_year
    select metric, max(year) as y from civic_indicators
     where organization_id = p_org and zone_id is not null and year <= p_year
       and metric in ('water_supply_hours', 'water_unfit_samples_pct')
     group by metric
  ),
  raw as (
    select z.id as zone_id,
           max(ci.value) filter (where ci.metric = 'complaints_registered' and ci.year = p_year and ci.category is null) as registered,
           max(ci.value) filter (where ci.metric = 'complaints_closed'     and ci.year = p_year and ci.category is null) as closed,
           max(ci.value) filter (where ci.metric = 'avg_days_to_close'     and ci.year = p_year and ci.category is null) as days,
           max(ci.value) filter (where ci.metric = 'water_supply_hours'
                                   and ci.year = (select y from latest where metric = 'water_supply_hours')) as hours,
           max(ci.value) filter (where ci.metric = 'water_unfit_samples_pct'
                                   and ci.year = (select y from latest where metric = 'water_unfit_samples_pct')) as unfit,
           sum(ci.value) filter (where ci.metric = 'air_quality_days' and ci.year = p_year and ci.category in ('Good', 'Satisfactory')) as good_days,
           sum(ci.value) filter (where ci.metric = 'air_quality_days' and ci.year = p_year and ci.category <> 'No data') as measured_days
      from city_zones z
      left join civic_indicators ci on ci.zone_id = z.id
     where z.organization_id = p_org
     group by z.id
  ),
  parts as (
    select zone_id,
           round(least(100, 100.0 * closed / nullif(registered, 0)), 1)    as complaint_closure,
           round(greatest(0, 100 * (1 - days / 60.0)), 1)                  as resolution_speed,
           round(least(100, 100.0 * hours / 24), 1)                        as water_supply,
           round(greatest(0, 100 - 20 * unfit), 1)                         as water_quality,
           round(100.0 * good_days / nullif(measured_days, 0), 1)          as air_quality
      from raw
  ),
  unioned as (
    select * from parts
    union all   -- city row = plain mean of the ward components
    select null::uuid, round(avg(complaint_closure), 1), round(avg(resolution_speed), 1),
           round(avg(water_supply), 1), round(avg(water_quality), 1), round(avg(air_quality), 1)
      from parts
  ),
  scored as (
    select u.*,
           (  coalesce(complaint_closure, 0) * (v_weights ->> 'complaint_closure')::numeric
            + coalesce(resolution_speed, 0)  * (v_weights ->> 'resolution_speed')::numeric
            + coalesce(water_supply, 0)      * (v_weights ->> 'water_supply')::numeric
            + coalesce(water_quality, 0)     * (v_weights ->> 'water_quality')::numeric
            + coalesce(air_quality, 0)       * (v_weights ->> 'air_quality')::numeric) as weighted,
           (  (complaint_closure is not null)::int * (v_weights ->> 'complaint_closure')::numeric
            + (resolution_speed is not null)::int  * (v_weights ->> 'resolution_speed')::numeric
            + (water_supply is not null)::int      * (v_weights ->> 'water_supply')::numeric
            + (water_quality is not null)::int     * (v_weights ->> 'water_quality')::numeric
            + (air_quality is not null)::int       * (v_weights ->> 'air_quality')::numeric) as weight_sum
      from unioned u
  )
  insert into health_index_snapshots (organization_id, zone_id, snapshot_date, score, components, weights)
  select p_org, zone_id, v_date, round(weighted / weight_sum, 1),
         jsonb_strip_nulls(jsonb_build_object(
           'complaint_closure', complaint_closure, 'resolution_speed', resolution_speed,
           'water_supply', water_supply, 'water_quality', water_quality, 'air_quality', air_quality)),
         v_weights
    from scored
   where weight_sum > 0;

  get diagnostics v_rows = row_count;
  return v_rows;
end $$;

revoke all on function app.compute_health_index(uuid, int) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- Model outputs. Models are trained offline from civic_indicators
-- (data/mumbai/ml/train.py) and their results loaded here, so pages read
-- stored results and no model runs on a page load.
-- ---------------------------------------------------------------------------
create table public.ml_models (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  id              text not null,                 -- 'ward-groups-2025'
  name            text not null,
  kind            text not null check (kind in ('clustering', 'forecast')),
  method          text not null,
  description     text not null,
  params          jsonb not null default '{}'::jsonb,
  metrics         jsonb not null default '{}'::jsonb,
  trained_on      text not null,
  trained_at      date not null,
  primary key (organization_id, id)
);

create table public.ml_ward_clusters (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  model_id        text not null,
  zone_id         uuid not null references public.city_zones(id) on delete cascade,
  cluster         int  not null,
  features        jsonb not null,                -- the ward's input values
  z               jsonb not null,                -- the same values as standard scores
  primary key (organization_id, model_id, zone_id),
  foreign key (organization_id, model_id) references public.ml_models (organization_id, id) on delete cascade
);

create table public.ml_forecasts (
  id              bigint generated always as identity primary key,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  model_id        text not null,
  zone_id         uuid references public.city_zones(id) on delete cascade,   -- null = whole city
  category        text,                                                       -- complaint issue; null = all
  year            int  not null,
  value           numeric not null,
  lower           numeric not null,
  upper           numeric not null,
  method          text not null,
  family          text not null,
  foreign key (organization_id, model_id) references public.ml_models (organization_id, id) on delete cascade
);
create index ml_forecasts_lookup on public.ml_forecasts (organization_id, family, year);

grant select, insert, update, delete on public.ml_models, public.ml_ward_clusters, public.ml_forecasts to authenticated;
grant all on public.ml_models, public.ml_ward_clusters, public.ml_forecasts to service_role;
grant usage, select on all sequences in schema public to authenticated, service_role;
revoke all on public.ml_models, public.ml_ward_clusters, public.ml_forecasts from anon;
revoke insert, update, delete on public.ml_models, public.ml_ward_clusters, public.ml_forecasts from authenticated;

select app.apply_tenant_policies('public.ml_models',        '{city_admin,dept_officer,field_worker,citizen}', '{}');
select app.apply_tenant_policies('public.ml_ward_clusters', '{city_admin,dept_officer,field_worker,citizen}', '{}');
select app.apply_tenant_policies('public.ml_forecasts',     '{city_admin,dept_officer,field_worker,citizen}', '{}');
