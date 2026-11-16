-- Tenant isolation test. Seeds two tenants, then checks as every role that
--   1. no row of the OTHER tenant is visible in any tenant table,
--   2. cross-tenant and privilege-escalating writes are rejected,
--   3. no table in "public" has RLS disabled.
-- Raises an exception (non-zero exit with ON_ERROR_STOP) on the first failure.
\set ON_ERROR_STOP on

begin;

-- ---- seed ------------------------------------------------------------------
insert into auth.users (id, email) values
  ('a0000000-0000-0000-0000-000000000001', 'admin@a.test'),
  ('a0000000-0000-0000-0000-000000000002', 'officer@a.test'),
  ('a0000000-0000-0000-0000-000000000003', 'field@a.test'),
  ('a0000000-0000-0000-0000-000000000004', 'citizen@a.test'),
  ('b0000000-0000-0000-0000-000000000001', 'admin@b.test');

create temp table t_org (tenant text primary key, id uuid) on commit drop;
grant select on t_org to authenticated;

insert into t_org values
  ('A', public.register_organization('a0000000-0000-0000-0000-000000000001', 'Tenant A', 'Admin A', 'admin@a.test', 'mumbai')),
  ('B', public.register_organization('b0000000-0000-0000-0000-000000000001', 'Tenant B', 'Admin B', 'admin@b.test'));

insert into public.users (id, organization_id, role, full_name, email)
select v.id::uuid, (select id from t_org where tenant = 'A'), v.role, v.name, v.email
  from (values
    ('a0000000-0000-0000-0000-000000000002', 'dept_officer', 'Officer A', 'officer@a.test'),
    ('a0000000-0000-0000-0000-000000000003', 'field_worker', 'Field A',   'field@a.test'),
    ('a0000000-0000-0000-0000-000000000004', 'citizen',      'Citizen A', 'citizen@a.test')
  ) as v(id, role, name, email);

-- one row in every remaining tenant table, for both tenants (tenant B has no city dataset)
insert into public.invitations (organization_id, email, role)
  select id, 'x@' || tenant || '.test', 'dept_officer' from t_org;
insert into public.usage_records (organization_id, metric) select id, 'ai_query' from t_org;
insert into public.api_keys (organization_id, name, key_prefix, key_hash)
  select id, 'k', 'civ_test', 'hash' from t_org;
insert into public.infrastructure_assets (organization_id, asset_type) select id, 'streetlight' from t_org;
insert into public.cities (organization_id, name) select id, 'Testville' from t_org where tenant = 'B';
insert into public.complaint_categories (organization_id, code, name) select id, 'roads', 'Roads' from t_org;
insert into public.complaints (organization_id, reference, description) select id, 'CMP-1', 'test' from t_org;

-- ---- helpers ---------------------------------------------------------------
create function pg_temp.login(p_user uuid) returns void language plpgsql as $$
declare v_meta jsonb;
begin
  select raw_app_meta_data into v_meta from auth.users where id = p_user;
  perform set_config('request.jwt.claims',
    jsonb_build_object('sub', p_user, 'role', 'authenticated', 'app_metadata', v_meta)::text, true);
end $$;

-- ---- 1. the claims trigger wrote org_id and role into the token ------------
do $$
declare v jsonb;
begin
  select raw_app_meta_data into v from auth.users where id = 'a0000000-0000-0000-0000-000000000002';
  if v ->> 'role' <> 'dept_officer' or (v ->> 'org_id')::uuid <> (select id from t_org where tenant = 'A') then
    raise exception 'FAIL claims sync: %', v;
  end if;
  raise notice 'ok   claims synced to auth.users';
end $$;

-- ---- 2. read isolation, every role x every tenant table --------------------
do $$
declare
  v_users constant text[][] := array[
    ['city_admin A',   'a0000000-0000-0000-0000-000000000001', 'A'],
    ['dept_officer A', 'a0000000-0000-0000-0000-000000000002', 'A'],
    ['field_worker A', 'a0000000-0000-0000-0000-000000000003', 'A'],
    ['citizen A',      'a0000000-0000-0000-0000-000000000004', 'A'],
    ['city_admin B',   'b0000000-0000-0000-0000-000000000001', 'B']];
  v_tables text[];
  u text[];
  t text;
  v_own uuid;
  v_foreign int;
  v_total int;
  v_checks int := 0;
begin
  select array_agg(c.table_name::text order by c.table_name) into v_tables
    from information_schema.columns c
    join information_schema.tables tb using (table_schema, table_name)
   where c.table_schema = 'public' and c.column_name = 'organization_id' and tb.table_type = 'BASE TABLE';

  foreach u slice 1 in array v_users loop
    perform pg_temp.login(u[2]::uuid);
    select id into v_own from t_org where tenant = u[3];
    set local role authenticated;

    foreach t in array v_tables loop
      execute format('select count(*) filter (where organization_id <> %L), count(*) from public.%I', v_own, t)
         into v_foreign, v_total;
      if v_foreign > 0 then
        raise exception 'FAIL % sees % foreign rows in %', u[1], v_foreign, t;
      end if;
      v_checks := v_checks + 1;
    end loop;

    execute format('select count(*) from public.organizations where id <> %L', v_own) into v_foreign;
    if v_foreign > 0 then raise exception 'FAIL % sees other organizations', u[1]; end if;
    select count(*) into v_total from public.organizations;
    if v_total <> 1 then raise exception 'FAIL % cannot see own organization', u[1]; end if;

    reset role;
  end loop;
  raise notice 'ok   read isolation: % table checks across % users, tables: %',
    v_checks, array_length(v_users, 1), v_tables;
end $$;

-- ---- 3. role scoping inside one tenant -------------------------------------
do $$
declare n int;
begin
  perform pg_temp.login('a0000000-0000-0000-0000-000000000001');
  set local role authenticated;
  select count(*) into n from public.users;
  if n <> 4 then raise exception 'FAIL city_admin should see 4 users, sees %', n; end if;
  select count(*) into n from public.city_zones;
  if n <> 24 then raise exception 'FAIL city_admin should see 24 Mumbai wards, sees %', n; end if;
  select count(*) into n from public.audit_logs;
  if n = 0 then raise exception 'FAIL city_admin should see audit rows'; end if;
  reset role;

  perform pg_temp.login('a0000000-0000-0000-0000-000000000004');
  set local role authenticated;
  select count(*) into n from public.users;
  if n <> 1 then raise exception 'FAIL citizen should see only own user row, sees %', n; end if;
  select count(*) into n from public.api_keys;
  if n <> 0 then raise exception 'FAIL citizen sees api keys'; end if;
  select count(*) into n from public.audit_logs;
  if n <> 0 then raise exception 'FAIL citizen sees audit logs'; end if;
  select count(*) into n from public.departments;
  if n <> 6 then raise exception 'FAIL citizen should see 6 departments, sees %', n; end if;
  reset role;

  perform pg_temp.login('a0000000-0000-0000-0000-000000000003');
  set local role authenticated;
  select count(*) into n from public.subscriptions;
  if n <> 0 then raise exception 'FAIL field_worker sees subscription'; end if;
  reset role;
  raise notice 'ok   role scoping inside a tenant';
end $$;

-- ---- 4. writes that must be rejected ---------------------------------------
create function pg_temp.must_fail(p_label text, p_sql text) returns void language plpgsql as $$
declare n int;
begin
  begin
    execute p_sql;
    get diagnostics n = row_count;
  exception when others then
    raise notice 'ok   blocked: % (%)', p_label, sqlerrm;
    return;
  end;
  if n = 0 then
    raise notice 'ok   blocked: % (0 rows affected)', p_label;
  else
    raise exception 'FAIL not blocked: % (% rows)', p_label, n;
  end if;
end $$;

do $$
declare
  v_a uuid := (select id from t_org where tenant = 'A');
  v_b uuid := (select id from t_org where tenant = 'B');
begin
  -- city admin of A
  perform pg_temp.login('a0000000-0000-0000-0000-000000000001');
  set local role authenticated;
  perform pg_temp.must_fail('admin A inserts department into B',
    format('insert into public.departments (organization_id, name, code) values (%L, ''x'', ''X'')', v_b));
  perform pg_temp.must_fail('admin A renames org B',
    format('update public.organizations set name = ''hacked'' where id = %L', v_b));
  perform pg_temp.must_fail('admin A upgrades own plan',
    format('update public.organizations set plan_code = ''enterprise'' where id = %L', v_a));
  perform pg_temp.must_fail('admin A promotes a user to super_admin',
    'update public.users set role = ''super_admin'' where id = ''a0000000-0000-0000-0000-000000000002''');
  perform pg_temp.must_fail('admin A moves a user into B',
    format('update public.users set organization_id = %L where id = ''a0000000-0000-0000-0000-000000000002''', v_b));
  perform pg_temp.must_fail('admin A deletes zones of B',
    format('delete from public.city_zones where organization_id = %L', v_b));
  perform pg_temp.must_fail('admin A edits audit log',
    'delete from public.audit_logs');
  perform pg_temp.must_fail('admin A calls register_organization',
    'select public.register_organization(gen_random_uuid(), ''x'', ''x'', ''x@x.test'')');
  reset role;

  -- citizen of A
  perform pg_temp.login('a0000000-0000-0000-0000-000000000004');
  set local role authenticated;
  perform pg_temp.must_fail('citizen makes self admin',
    'update public.users set role = ''city_admin'' where id = ''a0000000-0000-0000-0000-000000000004''');
  perform pg_temp.must_fail('citizen inserts department',
    format('insert into public.departments (organization_id, name, code) values (%L, ''x'', ''Y'')', v_a));
  reset role;

  -- not signed in
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  perform pg_temp.must_fail('anon reads organizations', 'select 1 from public.organizations limit 1');
  reset role;
end $$;

-- ---- 5. allowed writes still work ------------------------------------------
do $$
declare n int;
begin
  perform pg_temp.login('a0000000-0000-0000-0000-000000000001');
  set local role authenticated;
  update public.organizations set name = 'Tenant A renamed' where id = (select id from t_org where tenant = 'A');
  get diagnostics n = row_count;
  if n <> 1 then raise exception 'FAIL admin cannot rename own org'; end if;
  insert into public.departments (organization_id, name, code)
    values ((select id from t_org where tenant = 'A'), 'Parks', 'PARKS');
  reset role;
  raise notice 'ok   allowed writes work';
end $$;

-- ---- 5b. published data + dashboard/map functions respect tenancy ----------
do $$
declare
  d jsonb;
  m jsonb;
begin
  perform pg_temp.login('a0000000-0000-0000-0000-000000000001');
  set local role authenticated;
  d := public.dashboard_data();
  m := public.map_data();
  -- values printed in the Praja 2026 report: Table 43 total for 2025, Table 3 closed, Table 29
  if (d #>> '{meta,year}')::int <> 2025 then raise exception 'FAIL latest year should be 2025'; end if;
  if (d #>> '{kpis,registered}')::int <> 130066 then raise exception 'FAIL 2025 complaints: %', d #>> '{kpis,registered}'; end if;
  if (d #>> '{kpis,closed}')::int <> 119458 then raise exception 'FAIL 2025 closed: %', d #>> '{kpis,closed}'; end if;
  if (d #>> '{kpis,avg_days}')::int <> 30 then raise exception 'FAIL 2025 avg days'; end if;
  if (d #>> '{kpis,waste_tpd}')::int <> 6955 then raise exception 'FAIL 2025 waste'; end if;
  if (d #>> '{kpis,water_hours}')::numeric <> 5.37 then raise exception 'FAIL water hours'; end if;
  if jsonb_array_length(d -> 'complaints_by_year') <> 10 or jsonb_array_length(d -> 'issues') <> 18
     or jsonb_array_length(d -> 'wards') <> 24 or jsonb_array_length(d #> '{aqi,grid}') <> 10 then
    raise exception 'FAIL dashboard series incomplete';
  end if;
  if (d #>> '{kpis,health_score}') is null then raise exception 'FAIL health score missing'; end if;
  if jsonb_array_length(m #> '{zones,features}') <> 24 then raise exception 'FAIL map should have 24 wards'; end if;

  d := public.dashboard_data(2019, (select id from public.city_zones where code = 'K/W'), null);
  if (d #>> '{kpis,registered}')::int <> 10399 then raise exception 'FAIL K/W 2019: %', d #>> '{kpis,registered}'; end if;
  d := public.dashboard_data(2018, null, 'Solid Waste Management (SWM)');
  if (d #>> '{kpis,registered}')::int <> 14494 then raise exception 'FAIL SWM 2018: %', d #>> '{kpis,registered}'; end if;
  -- model results are loaded with the dataset
  d := public.ml_data();
  if (d #>> '{models,clustering,id}') is null or jsonb_array_length(d -> 'wards') <> 24 then
    raise exception 'FAIL ward groups missing';
  end if;
  if (d #>> '{forecast,year}')::int <> 2026 or (d #>> '{forecast,lower}')::numeric > (d #>> '{forecast,value}')::numeric
     or (d #>> '{forecast,upper}')::numeric < (d #>> '{forecast,value}')::numeric then
    raise exception 'FAIL city forecast malformed: %', d -> 'forecast';
  end if;
  if jsonb_array_length(d -> 'ward_forecasts') <> 24 then raise exception 'FAIL ward forecasts missing'; end if;
  reset role;

  perform pg_temp.login('b0000000-0000-0000-0000-000000000001');   -- admin of B: nothing from A
  set local role authenticated;
  d := public.ml_data();
  if d -> 'models' <> '{}'::jsonb or jsonb_array_length(d -> 'wards') <> 0 or d -> 'forecast' <> 'null'::jsonb then
    raise exception 'FAIL admin B sees tenant A models';
  end if;
  d := public.dashboard_data();
  m := public.map_data();
  if (d #>> '{meta,has_data}')::boolean then raise exception 'FAIL admin B sees tenant A data'; end if;
  if jsonb_array_length(m #> '{zones,features}') <> 0 then raise exception 'FAIL admin B map leaks tenant A wards'; end if;
  reset role;
  raise notice 'ok   dashboard_data, map_data and ml_data return the published figures and models, tenant-scoped';
end $$;

-- ---- 6. plan limit (free = 5 users) ----------------------------------------
do $$
begin
  insert into auth.users (id, email) values
    ('a0000000-0000-0000-0000-000000000005', 'u5@a.test'),
    ('a0000000-0000-0000-0000-000000000006', 'u6@a.test');
  insert into public.users (id, organization_id, role, full_name, email)
    values ('a0000000-0000-0000-0000-000000000005', (select id from t_org where tenant = 'A'), 'citizen', 'U5', 'u5@a.test');
  begin
    insert into public.users (id, organization_id, role, full_name, email)
      values ('a0000000-0000-0000-0000-000000000006', (select id from t_org where tenant = 'A'), 'citizen', 'U6', 'u6@a.test');
    raise exception 'FAIL sixth user allowed on free plan';
  exception when sqlstate 'P0001' then
    if sqlerrm like 'FAIL%' then raise; end if;
    raise notice 'ok   plan limit: %', sqlerrm;
  end;
end $$;

-- ---- 7. every public table has RLS on --------------------------------------
do $$
declare v text;
begin
  select string_agg(table_name, ', ') into v from app.tables_without_rls;
  if v is not null then raise exception 'FAIL tables without RLS: %', v; end if;
  raise notice 'ok   every public table has RLS enabled';
end $$;

rollback;
\echo ALL RLS TESTS PASSED
