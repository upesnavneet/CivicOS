-- CivicOS 0007: read functions for the dashboard and the map.
-- SECURITY INVOKER (the default): they run as the signed-in user, so RLS limits
-- every table they touch to the caller's organization.
-- All figures come from civic_indicators, i.e. from published reports.

-- ---------------------------------------------------------------------------
-- One row per ward with the figures for a year. p_issue null = all complaints;
-- ward-level issue figures exist only for the issues the reports break down by ward.
-- Water, air and per-person waste figures are published for few years, so those
-- columns always carry the latest published year and say which year it is.
-- ---------------------------------------------------------------------------
create or replace function public.ward_stats(p_year int, p_issue text default null)
returns table (
  zone_id uuid, code text, name text, population int,
  registered numeric, closed numeric, closed_pct numeric, avg_days numeric, per_10k numeric,
  waste_tpd numeric, waste_per_capita numeric,
  water_hours numeric, water_hours_year int, water_unfit_pct numeric, water_unfit_year int,
  air_good_days numeric, air_measured_days numeric, air_year int,
  slum_pct numeric, health_score numeric, ward_group int
)
language sql stable set search_path = public, extensions as $$
  with latest as (
    select metric, max(year) as y from civic_indicators
     where zone_id is not null
       and metric in ('water_supply_hours', 'water_unfit_samples_pct', 'air_quality_days', 'waste_per_capita')
     group by metric
  ),
  y as (
    select (select y from latest where metric = 'water_supply_hours')      as hours_y,
           (select y from latest where metric = 'water_unfit_samples_pct') as unfit_y,
           (select y from latest where metric = 'air_quality_days')        as air_y,
           (select y from latest where metric = 'waste_per_capita')        as percap_y
  )
  select z.id, z.code, z.name, z.population,
         s.registered, s.closed,
         round(100.0 * s.closed / nullif(s.registered, 0), 1),
         s.avg_days,
         round(10000.0 * s.registered / nullif(z.population, 0), 1),
         s.waste_tpd, s.waste_per_capita,
         s.water_hours, case when s.water_hours is not null then y.hours_y end,
         s.unfit, case when s.unfit is not null then y.unfit_y end,
         s.good_days, s.measured_days, case when s.measured_days is not null then y.air_y end,
         s.slum_pct,
         (select h.score from health_index_snapshots h
           where h.zone_id = z.id order by h.snapshot_date desc limit 1),
         (select c.cluster from ml_ward_clusters c where c.zone_id = z.id limit 1)
    from city_zones z
   cross join y
   cross join lateral (
     select max(ci.value) filter (where ci.metric = 'complaints_registered' and ci.year = p_year and ci.category is not distinct from p_issue) as registered,
            max(ci.value) filter (where ci.metric = 'complaints_closed'     and ci.year = p_year and ci.category is not distinct from p_issue) as closed,
            max(ci.value) filter (where ci.metric = 'avg_days_to_close'     and ci.year = p_year and ci.category is not distinct from p_issue) as avg_days,
            max(ci.value) filter (where ci.metric = 'waste_tonnes_per_day'  and ci.year = p_year)      as waste_tpd,
            max(ci.value) filter (where ci.metric = 'waste_per_capita'      and ci.year = y.percap_y)  as waste_per_capita,
            max(ci.value) filter (where ci.metric = 'water_supply_hours'    and ci.year = y.hours_y)   as water_hours,
            max(ci.value) filter (where ci.metric = 'water_unfit_samples_pct' and ci.year = y.unfit_y) as unfit,
            sum(ci.value) filter (where ci.metric = 'air_quality_days' and ci.year = y.air_y and ci.category in ('Good', 'Satisfactory')) as good_days,
            sum(ci.value) filter (where ci.metric = 'air_quality_days' and ci.year = y.air_y and ci.category <> 'No data') as measured_days,
            max(ci.value) filter (where ci.metric = 'slum_population_pct') as slum_pct
       from civic_indicators ci where ci.zone_id = z.id
   ) s
$$;

-- ---------------------------------------------------------------------------
-- Dashboard payload. Scope = one ward (p_zone) or the whole city (null).
-- ---------------------------------------------------------------------------
create or replace function public.dashboard_data(
  p_year  int  default null,
  p_zone  uuid default null,
  p_issue text default null
) returns jsonb
language plpgsql stable set search_path = public, extensions as $$
declare
  v_year int;
  v_out  jsonb;
begin
  select coalesce(p_year, max(year)) into v_year from civic_indicators where metric = 'complaints_registered';
  if v_year is null then
    return jsonb_build_object('meta', jsonb_build_object('has_data', false));
  end if;

  with s as materialized (          -- indicators in scope: this ward, or city-level rows
    select * from civic_indicators ci where ci.zone_id is not distinct from p_zone
  ),
  w as materialized (select * from public.ward_stats(v_year, p_issue)),
  pick as (                         -- single values for the KPI row
    select
      (select value from s where metric = 'complaints_registered' and year = v_year     and category is not distinct from p_issue) as registered,
      (select value from s where metric = 'complaints_registered' and year = v_year - 1 and category is not distinct from p_issue) as registered_prev,
      (select value from s where metric = 'complaints_closed'     and year = v_year     and category is not distinct from p_issue) as closed,
      (select value from s where metric = 'avg_days_to_close'     and year = v_year     and category is not distinct from p_issue) as avg_days,
      (select value from s where metric = 'waste_tonnes_per_day'  and year = v_year) as waste_tpd,
      (select value from s where metric = 'water_unfit_samples_pct' and year = v_year) as water_unfit_pct,
      (select round(avg(value), 0) from civic_indicators where metric = 'aqi_monthly_avg' and year = v_year) as aqi_avg
  ),
  hours as (select value, year from s where metric = 'water_supply_hours' order by year desc limit 1),
  health as (
    select h.* from health_index_snapshots h
     where h.zone_id is not distinct from p_zone order by h.snapshot_date desc limit 1
  )
  select jsonb_build_object(
    'meta', jsonb_build_object(
      'has_data', true, 'year', v_year, 'issue', p_issue,
      'years',  (select jsonb_agg(distinct year order by year) from civic_indicators where metric = 'complaints_registered'),
      'zone',   (select jsonb_build_object('id', id, 'code', code, 'name', name, 'population', population) from city_zones where id = p_zone),
      'ward_issues', (select jsonb_agg(distinct category order by category) from civic_indicators
                       where metric = 'complaints_registered' and zone_id is not null and category is not null),
      'closure_years', (select jsonb_agg(distinct year order by year) from s
                         where metric = 'complaints_closed' and category is not distinct from p_issue)),

    'kpis', (select jsonb_build_object(
      'registered', registered, 'registered_prev', registered_prev,
      'closed', closed, 'closed_pct', round(100.0 * closed / nullif(registered, 0), 1),
      'pending', registered - closed, 'avg_days', avg_days,
      'waste_tpd', waste_tpd, 'water_unfit_pct', water_unfit_pct, 'aqi_avg', aqi_avg,
      'water_hours', (select value from hours), 'water_hours_year', (select year from hours),
      'health_score', (select score from health)) from pick),

    'complaints_by_year', coalesce((
      select jsonb_agg(jsonb_build_object('year', year, 'registered', value) order by year)
        from s where metric = 'complaints_registered' and category is not distinct from p_issue), '[]'::jsonb),

    -- city-level issue breakdown for the year (the reports do not break all issues down by ward)
    'issues', coalesce((
      select jsonb_agg(jsonb_build_object('issue', category, 'registered', registered, 'closed', closed,
                                          'closed_pct', round(100.0 * closed / nullif(registered, 0), 1),
                                          'avg_days', avg_days) order by registered desc)
        from (
          select category,
                 max(value) filter (where metric = 'complaints_registered') as registered,
                 max(value) filter (where metric = 'complaints_closed')     as closed,
                 max(value) filter (where metric = 'avg_days_to_close')     as avg_days
            from civic_indicators
           where zone_id is null and year = v_year and category is not null
             and metric in ('complaints_registered', 'complaints_closed', 'avg_days_to_close')
           group by category
        ) t where registered is not null), '[]'::jsonb),

    'wards', coalesce((select jsonb_agg(to_jsonb(w) - 'zone_id' order by w.code) from w), '[]'::jsonb),

    'aqi', jsonb_build_object(
      'months', coalesce((
        select jsonb_agg(jsonb_build_object('month', month, 'current', cur, 'previous', prev) order by month)
          from (select month,
                       max(value) filter (where year = v_year)     as cur,
                       max(value) filter (where year = v_year - 1) as prev
                  from civic_indicators where metric = 'aqi_monthly_avg' and year in (v_year, v_year - 1)
                 group by month) t), '[]'::jsonb),
      'grid', coalesce((
        select jsonb_agg(jsonb_build_object('year', year, 'values', vals) order by year)
          from (select year, jsonb_agg(value order by month) as vals
                  from civic_indicators where metric = 'aqi_monthly_avg' group by year) t), '[]'::jsonb),
      'ward_days', coalesce((
        select jsonb_agg(jsonb_build_object('level', category, 'days', value))
          from s where metric = 'air_quality_days' and zone_id is not null), '[]'::jsonb)),

    'waste_by_year', coalesce((
      select jsonb_agg(jsonb_build_object('year', year, 'tonnes_per_day', value) order by year)
        from s where metric = 'waste_tonnes_per_day'), '[]'::jsonb),

    'water', jsonb_build_object(
      'balance', (select jsonb_object_agg(metric, value) from civic_indicators
                   where zone_id is null and metric in ('water_yield_mld', 'water_enroute_loss_mld', 'water_supply_mld', 'water_demand_mld', 'water_gap_mld')),
      'unfit_by_year', coalesce((
        select jsonb_agg(jsonb_build_object('year', year, 'pct', value) order by year)
          from s where metric = 'water_unfit_samples_pct'), '[]'::jsonb),
      'zones_by_hours', coalesce((
        select jsonb_agg(jsonb_build_object('band', band, 'zones', zones) order by ord)
          from (select ci.category as band, sum(ci.value) as zones, min(b.ord) as ord
                  from civic_indicators ci
                  join (values ('<=2 hrs', 1), ('>2 to <=4 hrs', 2), ('>4 to <=8 hrs', 3), ('>8 to <=12 hrs', 4),
                               ('>12 to <=18 hrs', 5), ('>18 to <24 hrs', 6), ('24 hrs', 7), ('Not available', 8)) as b(band, ord)
                    on b.band = ci.category
                 where ci.metric = 'water_zones_by_hours' and (p_zone is null or ci.zone_id = p_zone)
                 group by ci.category) t), '[]'::jsonb)),

    'health', jsonb_build_object(
      'score', (select score from health), 'year', (select extract(year from snapshot_date)::int from health),
      'components', (select components from health), 'weights', (select weights from health)),

    'sources', coalesce((
      select jsonb_object_agg(id, jsonb_build_object('publisher', publisher, 'report', report, 'table', table_ref,
                                                     'page', page, 'title', title, 'url', url, 'note', note))
        from data_sources), '{}'::jsonb)
  ) into v_out;

  return v_out;
end $$;

-- ---------------------------------------------------------------------------
-- Map: ward polygons with the same figures as properties
-- ---------------------------------------------------------------------------
create or replace function public.map_data(p_year int default null, p_issue text default null)
returns jsonb
language plpgsql stable set search_path = public, extensions as $$
declare
  v_year int;
begin
  select coalesce(p_year, max(year)) into v_year from civic_indicators where metric = 'complaints_registered';
  return jsonb_build_object(
    'year', v_year,
    'years', (select jsonb_agg(distinct year order by year) from civic_indicators where metric = 'complaints_registered'),
    'ward_issues', (select jsonb_agg(distinct category order by category) from civic_indicators
                     where metric = 'complaints_registered' and zone_id is not null and category is not null),
    'groups', (select params -> 'groups' from ml_models where kind = 'clustering' limit 1),
    'zones', jsonb_build_object('type', 'FeatureCollection', 'features', coalesce((
      select jsonb_agg(jsonb_build_object(
               'type', 'Feature',
               'geometry', st_asgeojson(z.boundary)::jsonb,
               'properties', to_jsonb(w) - 'zone_id') order by w.code)
        from public.ward_stats(v_year, p_issue) w
        join city_zones z on z.id = w.zone_id
       where z.boundary is not null), '[]'::jsonb)));
end $$;

-- ---------------------------------------------------------------------------
-- Models page: model cards, ward groups, and the forecast for one series.
-- Series = (p_zone, p_issue); null/null is the whole city, all issues.
-- ---------------------------------------------------------------------------
create or replace function public.ml_data(p_zone uuid default null, p_issue text default null)
returns jsonb
language sql stable set search_path = public, extensions as $$
  select jsonb_build_object(
    'models', coalesce((select jsonb_object_agg(kind, to_jsonb(m) - 'organization_id') from ml_models m), '{}'::jsonb),
    'wards', coalesce((
      select jsonb_agg(jsonb_build_object('code', z.code, 'name', z.name, 'cluster', c.cluster,
                                          'features', c.features, 'z', c.z) order by c.cluster, z.code)
        from ml_ward_clusters c join city_zones z on z.id = c.zone_id), '[]'::jsonb),
    'zone', (select jsonb_build_object('id', id, 'code', code, 'name', name) from city_zones where id = p_zone),
    'issue', p_issue,
    'history', coalesce((
      select jsonb_agg(jsonb_build_object('year', year, 'value', value) order by year)
        from civic_indicators
       where metric = 'complaints_registered' and zone_id is not distinct from p_zone
         and category is not distinct from p_issue), '[]'::jsonb),
    'forecast', (
      select to_jsonb(f) - 'organization_id' - 'id' - 'zone_id'
        from ml_forecasts f
       where f.zone_id is not distinct from p_zone and f.category is not distinct from p_issue
       limit 1),
    'ward_forecasts', coalesce((
      select jsonb_agg(jsonb_build_object('code', z.code, 'name', z.name, 'value', f.value, 'lower', f.lower, 'upper', f.upper,
                                          'last', (select ci.value from civic_indicators ci
                                                    where ci.zone_id = z.id and ci.metric = 'complaints_registered'
                                                      and ci.category is not distinct from p_issue and ci.year = f.year - 1))
                       order by z.code)
        from ml_forecasts f join city_zones z on z.id = f.zone_id
       where f.category is not distinct from p_issue), '[]'::jsonb),
    'issues_with_forecasts', coalesce((
      select jsonb_agg(distinct category order by category) from ml_forecasts where category is not null and zone_id is null), '[]'::jsonb),
    'ward_issues', coalesce((
      select jsonb_agg(distinct category order by category) from ml_forecasts where category is not null and zone_id is not null), '[]'::jsonb)
  )
$$;

revoke all on function public.ml_data(uuid, text) from public, anon;
grant execute on function public.ml_data(uuid, text) to authenticated, service_role;
revoke all on function public.ward_stats(int, text) from public, anon;
revoke all on function public.dashboard_data(int, uuid, text) from public, anon;
revoke all on function public.map_data(int, text) from public, anon;
grant execute on function public.ward_stats(int, text) to authenticated, service_role;
grant execute on function public.dashboard_data(int, uuid, text) to authenticated, service_role;
grant execute on function public.map_data(int, text) to authenticated, service_role;
