-- CivicOS: all migrations in order (generated from supabase/migrations). Paste into the Supabase SQL Editor and run once on a new project.

-- ============================================================================
-- 0001_extensions.sql
-- ============================================================================
-- CivicOS 0001: extensions
-- Supabase keeps extensions in the "extensions" schema, which is on the search_path.
create extension if not exists pgcrypto with schema extensions;
create extension if not exists postgis  with schema extensions;
create extension if not exists vector   with schema extensions;

-- ============================================================================
-- 0002_saas.sql
-- ============================================================================
-- CivicOS 0002: SaaS core (tenants, users, roles, plans, audit)

create schema if not exists app;
grant usage on schema app to anon, authenticated, service_role;

-- ---------------------------------------------------------------------------
-- JWT helpers. org_id / role / department_id live in the token's app_metadata
-- and are kept in sync from public.users by a trigger (see below).
-- ---------------------------------------------------------------------------
create or replace function app.org_id() returns uuid
language sql stable as $$
  select nullif(auth.jwt() -> 'app_metadata' ->> 'org_id', '')::uuid
$$;

create or replace function app.role() returns text
language sql stable as $$
  select auth.jwt() -> 'app_metadata' ->> 'role'
$$;

create or replace function app.department_id() returns uuid
language sql stable as $$
  select nullif(auth.jwt() -> 'app_metadata' ->> 'department_id', '')::uuid
$$;

create or replace function app.is_super_admin() returns boolean
language sql stable as $$
  select coalesce(app.role() = 'super_admin', false)
$$;

-- ---------------------------------------------------------------------------
-- Reference tables (global, not tenant-owned)
-- ---------------------------------------------------------------------------
create table public.plans (
  code   text primary key,
  name   text not null,
  limits jsonb not null default '{}'::jsonb,   -- null value = unlimited
  sort   int  not null default 0
);

create table public.roles (
  code text primary key,
  name text not null,
  rank int  not null
);

create table public.permissions (
  code        text primary key,
  description text not null
);

create table public.role_permissions (
  role_code       text not null references public.roles(code) on delete cascade,
  permission_code text not null references public.permissions(code) on delete cascade,
  primary key (role_code, permission_code)
);

-- ---------------------------------------------------------------------------
-- Tenant tables
-- ---------------------------------------------------------------------------
create table public.organizations (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  slug       text not null unique,
  plan_code  text not null default 'free' references public.plans(code),
  status     text not null default 'active' check (status in ('active', 'suspended')),
  created_at timestamptz not null default now()
);

create table public.users (
  id              uuid primary key references auth.users(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  role            text not null references public.roles(code),
  department_id   uuid,                         -- FK added in 0003 (departments)
  full_name       text not null,
  email           text not null,
  is_active       boolean not null default true,
  created_at      timestamptz not null default now()
);
create index users_org_idx on public.users (organization_id);

create table public.subscriptions (
  id                 uuid primary key default gen_random_uuid(),
  organization_id    uuid not null references public.organizations(id) on delete cascade,
  plan_code          text not null references public.plans(code),
  status             text not null default 'active'
                     check (status in ('trialing', 'active', 'past_due', 'canceled')),
  current_period_end timestamptz,
  provider           text,                      -- e.g. 'razorpay_test'
  provider_ref       text,
  created_at         timestamptz not null default now()
);
create index subscriptions_org_idx on public.subscriptions (organization_id);

create table public.invitations (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  email           text not null,
  role            text not null references public.roles(code),
  department_id   uuid,
  token           text not null unique
                  default replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''),
  invited_by      uuid references public.users(id) on delete set null,
  expires_at      timestamptz not null default now() + interval '7 days',
  accepted_at     timestamptz,
  created_at      timestamptz not null default now()
);
create index invitations_org_idx on public.invitations (organization_id);

create table public.usage_records (
  id              bigint generated always as identity primary key,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id         uuid references public.users(id) on delete set null,
  metric          text not null,                -- 'ai_query', 'document_upload', 'api_call'
  quantity        int  not null default 1,
  recorded_at     timestamptz not null default now()
);
create index usage_org_metric_idx on public.usage_records (organization_id, metric, recorded_at);

create table public.api_keys (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name            text not null,
  key_prefix      text not null,                -- first 8 chars, shown in the UI
  key_hash        text not null,                -- sha256 of the full key; the key itself is never stored
  created_by      uuid references public.users(id) on delete set null,
  last_used_at    timestamptz,
  revoked_at      timestamptz,
  created_at      timestamptz not null default now()
);
create index api_keys_org_idx on public.api_keys (organization_id);

-- No FK on organization_id: audit rows must outlive the rows they describe.
create table public.audit_logs (
  id              bigint generated always as identity primary key,
  organization_id uuid,
  actor_id        uuid,
  action          text not null,                -- INSERT / UPDATE / DELETE
  entity          text not null,                -- table name
  entity_id       text,
  diff            jsonb,
  created_at      timestamptz not null default now()
);
create index audit_org_idx on public.audit_logs (organization_id, created_at desc);

-- ---------------------------------------------------------------------------
-- Keep JWT claims in sync with public.users
-- ---------------------------------------------------------------------------
create or replace function app.sync_user_claims() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  update auth.users
     set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb)
         || jsonb_build_object(
              'org_id',        new.organization_id,
              'role',          new.role,
              'department_id', new.department_id)
   where id = new.id;
  return new;
end $$;

create trigger users_sync_claims
after insert or update of organization_id, role, department_id on public.users
for each row execute function app.sync_user_claims();

-- ---------------------------------------------------------------------------
-- Plan limits
-- ---------------------------------------------------------------------------
create or replace function app.plan_limit(p_org uuid, p_key text) returns int
language sql stable security definer set search_path = '' as $$
  select (p.limits ->> p_key)::int
    from public.organizations o
    join public.plans p on p.code = o.plan_code
   where o.id = p_org
$$;

create or replace function app.enforce_user_limit() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  v_limit int := app.plan_limit(new.organization_id, 'max_users');
  v_count int;
begin
  if v_limit is null then return new; end if;
  select count(*) into v_count from public.users where organization_id = new.organization_id;
  if v_count >= v_limit then
    raise exception 'Plan limit reached: this plan allows % users', v_limit
      using errcode = 'P0001';
  end if;
  return new;
end $$;

create trigger users_enforce_limit
before insert on public.users
for each row execute function app.enforce_user_limit();

-- ---------------------------------------------------------------------------
-- Audit trigger (generic)
-- ---------------------------------------------------------------------------
create or replace function app.audit() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  v_old jsonb;
  v_new jsonb;
  v_row jsonb;
begin
  if tg_op <> 'INSERT' then v_old := to_jsonb(old) - 'key_hash'; end if;
  if tg_op <> 'DELETE' then v_new := to_jsonb(new) - 'key_hash'; end if;
  v_row := coalesce(v_new, v_old);

  insert into public.audit_logs (organization_id, actor_id, action, entity, entity_id, diff)
  values (
    case when tg_table_name = 'organizations'
         then (v_row ->> 'id')::uuid
         else (v_row ->> 'organization_id')::uuid end,
    auth.uid(),
    tg_op,
    tg_table_name,
    v_row ->> 'id',
    case tg_op
      when 'INSERT' then jsonb_build_object('new', v_new)
      when 'DELETE' then jsonb_build_object('old', v_old)
      else jsonb_build_object('old', v_old, 'new', v_new)
    end
  );
  return null;
end $$;

create trigger audit_organizations after insert or update or delete on public.organizations
  for each row execute function app.audit();
create trigger audit_users after insert or update or delete on public.users
  for each row execute function app.audit();
create trigger audit_subscriptions after insert or update or delete on public.subscriptions
  for each row execute function app.audit();
create trigger audit_invitations after insert or update or delete on public.invitations
  for each row execute function app.audit();
create trigger audit_api_keys after insert or update or delete on public.api_keys
  for each row execute function app.audit();

-- ---------------------------------------------------------------------------
-- Reference data
-- ---------------------------------------------------------------------------
insert into public.plans (code, name, limits, sort) values
  ('free',       'Free / Demo',  '{"max_users": 5,  "max_documents": 10,  "ai_queries_per_month": 50,   "advanced_analytics": false, "rag": false, "predictions": false, "audit_logs": false}', 1),
  ('pro',        'Professional', '{"max_users": 50, "max_documents": 500, "ai_queries_per_month": 2000, "advanced_analytics": true,  "rag": true,  "predictions": true,  "audit_logs": false}', 2),
  ('enterprise', 'Enterprise',   '{"max_users": null, "max_documents": null, "ai_queries_per_month": null, "advanced_analytics": true, "rag": true, "predictions": true, "audit_logs": true}', 3);

insert into public.roles (code, name, rank) values
  ('super_admin',  'Super Administrator', 100),
  ('city_admin',   'City Administrator',   80),
  ('dept_officer', 'Department Officer',   60),
  ('field_worker', 'Field Worker',         40),
  ('citizen',      'Citizen',              10);

insert into public.permissions (code, description) values
  ('platform.manage',          'Manage all organizations, plans and platform settings'),
  ('org.manage',               'Edit organization settings, departments and users'),
  ('org.billing',              'View and change the subscription'),
  ('org.audit',                'View audit logs and API keys'),
  ('dashboard.view',           'View the city intelligence dashboard'),
  ('modules.view',             'View water, waste and traffic modules'),
  ('map.view',                 'View the GIS map'),
  ('documents.upload',         'Upload documents to the knowledge base'),
  ('assistant.use',            'Ask the CivicOS assistant'),
  ('assistant.public',         'Ask the public assistant (public documents only)'),
  ('complaints.submit',        'Submit and track own complaints'),
  ('complaints.review',        'Review complaints and set final severity'),
  ('complaints.assign',        'Assign complaints and maintenance tasks'),
  ('tasks.update',             'Update assigned tasks and upload field reports'),
  ('recommendations.decide',   'Accept, reject or assign AI recommendations'),
  ('reports.export',           'Export reports as CSV or PDF');

insert into public.role_permissions (role_code, permission_code)
select 'super_admin', code from public.permissions;

insert into public.role_permissions (role_code, permission_code)
select 'city_admin', code from public.permissions
 where code not in ('platform.manage', 'assistant.public', 'complaints.submit');

insert into public.role_permissions (role_code, permission_code) values
  ('dept_officer', 'dashboard.view'), ('dept_officer', 'modules.view'), ('dept_officer', 'map.view'),
  ('dept_officer', 'documents.upload'), ('dept_officer', 'assistant.use'),
  ('dept_officer', 'complaints.review'), ('dept_officer', 'complaints.assign'),
  ('dept_officer', 'tasks.update'), ('dept_officer', 'recommendations.decide'),
  ('dept_officer', 'reports.export'),
  ('field_worker', 'map.view'), ('field_worker', 'tasks.update'),
  ('citizen', 'complaints.submit'), ('citizen', 'assistant.public');

-- ============================================================================
-- 0003_city.sql
-- ============================================================================
-- CivicOS 0003: city, zones, departments, assets, health index

create table public.cities (
  id                    uuid primary key default gen_random_uuid(),
  organization_id       uuid not null references public.organizations(id) on delete cascade,
  name                  text not null,
  state                 text,
  boundary              geometry(MultiPolygon, 4326),
  is_synthetic_geometry boolean not null default false,
  created_at            timestamptz not null default now()
);
create index cities_org_idx on public.cities (organization_id);
create index cities_boundary_gix on public.cities using gist (boundary);

create table public.city_zones (
  id                    uuid primary key default gen_random_uuid(),
  organization_id       uuid not null references public.organizations(id) on delete cascade,
  city_id               uuid not null references public.cities(id) on delete cascade,
  name                  text not null,
  code                  text not null,
  boundary              geometry(MultiPolygon, 4326),
  population            int,
  is_synthetic_geometry boolean not null default false,
  created_at            timestamptz not null default now(),
  unique (city_id, code)
);
create index city_zones_org_idx on public.city_zones (organization_id);
create index city_zones_boundary_gix on public.city_zones using gist (boundary);

create table public.departments (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name            text not null,
  code            text not null,
  created_at      timestamptz not null default now(),
  unique (organization_id, code)
);
create index departments_org_idx on public.departments (organization_id);

alter table public.users
  add constraint users_department_fk
  foreign key (department_id) references public.departments(id) on delete set null;

alter table public.invitations
  add constraint invitations_department_fk
  foreign key (department_id) references public.departments(id) on delete set null;

create table public.infrastructure_assets (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  zone_id         uuid references public.city_zones(id) on delete set null,
  department_id   uuid references public.departments(id) on delete set null,
  asset_type      text not null,               -- streetlight, drain, public_building, ...
  name            text,
  geom            geometry(Geometry, 4326),
  condition_score numeric(5,2) check (condition_score between 0 and 100),
  installed_on    date,
  is_synthetic    boolean not null default false,
  created_at      timestamptz not null default now()
);
create index assets_org_idx on public.infrastructure_assets (organization_id);
create index assets_zone_idx on public.infrastructure_assets (zone_id);
create index assets_geom_gix on public.infrastructure_assets using gist (geom);

-- Stores the inputs with the score so the index stays explainable (prototype, not an official rating).
create table public.health_index_snapshots (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  zone_id         uuid references public.city_zones(id) on delete cascade,  -- null = whole city
  snapshot_date   date not null,
  score           numeric(5,2) not null check (score between 0 and 100),
  components      jsonb not null,              -- {"water": 71.2, "waste": 64.0, ...}
  weights         jsonb not null,              -- {"water": 0.25, ...}
  created_at      timestamptz not null default now()
);
create index health_org_date_idx on public.health_index_snapshots (organization_id, snapshot_date);
create unique index health_unique_idx on public.health_index_snapshots
  (organization_id, coalesce(zone_id, '00000000-0000-0000-0000-000000000000'::uuid), snapshot_date);

-- ---------------------------------------------------------------------------
-- Defaults for a new tenant: departments, plus the city dataset if one is
-- chosen at registration. 'mumbai' loads the published BMC ward data
-- (see 0008_mumbai_data.sql). No synthetic data is ever generated.
-- ---------------------------------------------------------------------------
create or replace function app.seed_city_defaults(p_org uuid, p_city text default null) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  insert into departments (organization_id, name, code) values
    (p_org, 'Water Supply',              'WATER'),
    (p_org, 'Solid Waste Management',    'WASTE'),
    (p_org, 'Roads & Public Works',      'ROADS'),
    (p_org, 'Traffic & Mobility',        'TRAFFIC'),
    (p_org, 'Electrical & Streetlights', 'ELEC'),
    (p_org, 'Drainage & Sewerage',       'DRAIN')
  on conflict (organization_id, code) do nothing;

  if p_city = 'mumbai' then
    perform app.load_mumbai_data(p_org);
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- Tenant registration. Called by the Next.js server with the service role
-- right after the auth user is created. Atomic: org + subscription + admin
-- user + city dataset, or nothing.
-- ---------------------------------------------------------------------------
create or replace function public.register_organization(
  p_user_id   uuid,
  p_org_name  text,
  p_full_name text,
  p_email     text,
  p_city      text default null
) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_org  uuid;
  v_slug text;
begin
  if coalesce(trim(p_org_name), '') = '' then
    raise exception 'Organization name is required';
  end if;
  if p_city is not null and p_city not in ('mumbai') then
    raise exception 'Unknown city dataset %', p_city;
  end if;

  v_slug := trim(both '-' from regexp_replace(lower(p_org_name), '[^a-z0-9]+', '-', 'g'))
            || '-' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 6);

  insert into organizations (name, slug) values (trim(p_org_name), v_slug)
  returning id into v_org;

  insert into subscriptions (organization_id, plan_code, status)
  values (v_org, 'free', 'active');

  insert into users (id, organization_id, role, full_name, email)
  values (p_user_id, v_org, 'city_admin', trim(p_full_name), lower(trim(p_email)));

  perform app.seed_city_defaults(v_org, p_city);
  return v_org;
end $$;

revoke all on function public.register_organization(uuid, text, text, text, text) from public, anon, authenticated;
grant execute on function public.register_organization(uuid, text, text, text, text) to service_role;
revoke all on function app.seed_city_defaults(uuid, text) from public, anon, authenticated;

-- ============================================================================
-- 0004_rls.sql
-- ============================================================================
-- CivicOS 0004: Row Level Security
-- Rule: every table in "public" has RLS enabled. Tenant tables are scoped by
-- organization_id = app.org_id() (from the JWT) plus a role list.

-- ---------------------------------------------------------------------------
-- Reusable policy generator. Later migrations call this for each new table:
--   select app.apply_tenant_policies('public.complaints', '{city_admin,dept_officer}', '{city_admin}');
-- Super admins get read access everywhere; their writes go through the service role.
-- ---------------------------------------------------------------------------
create or replace function app.apply_tenant_policies(
  p_table       regclass,
  p_read_roles  text[],
  p_write_roles text[]
) returns void
language plpgsql as $$
declare
  v_read  text := format(
    '(select app.is_super_admin()) or (organization_id = (select app.org_id()) and (select app.role()) = any (%L::text[]))',
    p_read_roles);
  v_write text := format(
    'organization_id = (select app.org_id()) and (select app.role()) = any (%L::text[])',
    p_write_roles);
begin
  execute format('alter table %s enable row level security', p_table);

  execute format('drop policy if exists tenant_read   on %s', p_table);
  execute format('drop policy if exists tenant_insert on %s', p_table);
  execute format('drop policy if exists tenant_update on %s', p_table);
  execute format('drop policy if exists tenant_delete on %s', p_table);

  execute format('create policy tenant_read on %s for select to authenticated using (%s)', p_table, v_read);

  if coalesce(array_length(p_write_roles, 1), 0) > 0 then
    execute format('create policy tenant_insert on %s for insert to authenticated with check (%s)', p_table, v_write);
    execute format('create policy tenant_update on %s for update to authenticated using (%s) with check (%s)', p_table, v_write, v_write);
    execute format('create policy tenant_delete on %s for delete to authenticated using (%s)', p_table, v_write);
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- Grants. RLS decides which rows; grants decide which verbs.
-- anon gets nothing yet (public citizen pages arrive in phase 3).
-- ---------------------------------------------------------------------------
grant select, insert, update, delete on all tables in schema public to authenticated;
grant all on all tables in schema public to service_role;
grant usage, select on all sequences in schema public to authenticated, service_role;
revoke all on all tables in schema public from anon;
revoke insert, update, delete on public.plans, public.roles, public.permissions,
  public.role_permissions, public.audit_logs from authenticated;

-- ---------------------------------------------------------------------------
-- Global reference tables: readable by any signed-in user, written by nobody
-- (service role only).
-- ---------------------------------------------------------------------------
alter table public.plans            enable row level security;
alter table public.roles            enable row level security;
alter table public.permissions      enable row level security;
alter table public.role_permissions enable row level security;

create policy ref_read on public.plans            for select to authenticated using (true);
create policy ref_read on public.roles            for select to authenticated using (true);
create policy ref_read on public.permissions      for select to authenticated using (true);
create policy ref_read on public.role_permissions for select to authenticated using (true);

-- ---------------------------------------------------------------------------
-- organizations: keyed by id, not organization_id
-- ---------------------------------------------------------------------------
alter table public.organizations enable row level security;

create policy org_read on public.organizations for select to authenticated
  using ((select app.is_super_admin()) or id = (select app.org_id()));

-- Admins may rename their org; plan and status change only via the service role.
create policy org_update on public.organizations for update to authenticated
  using (id = (select app.org_id()) and (select app.role()) = 'city_admin')
  with check (id = (select app.org_id()) and (select app.role()) = 'city_admin');

revoke update on public.organizations from authenticated;
grant update (name) on public.organizations to authenticated;

-- ---------------------------------------------------------------------------
-- users: staff see their org; everyone sees their own row; admins manage
-- ---------------------------------------------------------------------------
select app.apply_tenant_policies('public.users', '{city_admin,dept_officer}', '{city_admin}');

create policy self_read on public.users for select to authenticated
  using (id = (select auth.uid()));

-- A city admin can manage users in their org but can never mint a super admin.
create policy no_super_admin_grant on public.users as restrictive for all to authenticated
  using (true) with check (role <> 'super_admin');

-- ---------------------------------------------------------------------------
-- Admin-only SaaS tables
-- ---------------------------------------------------------------------------
select app.apply_tenant_policies('public.subscriptions', '{city_admin}', '{}');
select app.apply_tenant_policies('public.invitations',   '{city_admin}', '{city_admin}');
select app.apply_tenant_policies('public.api_keys',      '{city_admin}', '{city_admin}');
select app.apply_tenant_policies('public.audit_logs',    '{city_admin}', '{}');
select app.apply_tenant_policies('public.usage_records', '{city_admin}', '{}');

create policy no_super_admin_invite on public.invitations as restrictive for all to authenticated
  using (true) with check (role <> 'super_admin');

-- Any member may record their own usage (the limit check itself is server-side).
create policy usage_insert_own on public.usage_records for insert to authenticated
  with check (organization_id = (select app.org_id()) and user_id = (select auth.uid()));
revoke update, delete on public.usage_records from authenticated;

-- ---------------------------------------------------------------------------
-- City tables
-- ---------------------------------------------------------------------------
select app.apply_tenant_policies('public.cities',
  '{city_admin,dept_officer,field_worker,citizen}', '{city_admin}');
select app.apply_tenant_policies('public.city_zones',
  '{city_admin,dept_officer,field_worker,citizen}', '{city_admin}');
select app.apply_tenant_policies('public.departments',
  '{city_admin,dept_officer,field_worker,citizen}', '{city_admin}');
select app.apply_tenant_policies('public.infrastructure_assets',
  '{city_admin,dept_officer,field_worker}', '{city_admin,dept_officer}');
select app.apply_tenant_policies('public.health_index_snapshots',
  '{city_admin,dept_officer,field_worker,citizen}', '{}');

-- ---------------------------------------------------------------------------
-- Guard: lists any public table that has RLS switched off. CI fails if this
-- returns rows (see supabase/tests).
-- ---------------------------------------------------------------------------
create or replace view app.tables_without_rls as
select c.relname as table_name
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public'
   and c.relkind = 'r'
   and not c.relrowsecurity
   and c.relname not in ('spatial_ref_sys');

-- ============================================================================
-- 0005_complaints.sql
-- ============================================================================
-- CivicOS 0005: complaints submitted through CivicOS itself (the citizen flow arrives in phase 3).
-- These tables hold only what real users submit. Published BMC complaint statistics
-- live in civic_indicators (0006), never here.

create table public.complaint_categories (
  id                uuid primary key default gen_random_uuid(),
  organization_id   uuid not null references public.organizations(id) on delete cascade,
  code              text not null,
  name              text not null,
  department_id     uuid references public.departments(id) on delete set null,
  default_sla_hours int  not null default 72,
  unique (organization_id, code)
);
create index complaint_categories_org_idx on public.complaint_categories (organization_id);

create table public.complaints (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  reference       text not null,
  citizen_id      uuid references public.users(id) on delete set null,
  category_id     uuid references public.complaint_categories(id) on delete set null,
  department_id   uuid references public.departments(id) on delete set null,
  zone_id         uuid references public.city_zones(id) on delete set null,
  lon             double precision,
  lat             double precision,
  geom            geometry(Point, 4326) generated always as (st_setsrid(st_makepoint(lon, lat), 4326)) stored,
  description     text not null,
  severity        text not null default 'medium' check (severity in ('low', 'medium', 'high', 'critical')),
  status          text not null default 'submitted'
                  check (status in ('submitted', 'classified', 'assigned', 'in_progress', 'resolved', 'verified')),
  created_at      timestamptz not null default now(),
  assigned_at     timestamptz,
  resolved_at     timestamptz
);
create index complaints_org_created_idx on public.complaints (organization_id, created_at);
create index complaints_zone_idx on public.complaints (zone_id);
create index complaints_citizen_idx on public.complaints (citizen_id);
create index complaints_geom_gix on public.complaints using gist (geom);

select app.apply_tenant_policies('public.complaint_categories',
  '{city_admin,dept_officer,field_worker,citizen}', '{city_admin}');
select app.apply_tenant_policies('public.complaints',
  '{city_admin,dept_officer}', '{city_admin,dept_officer}');

create policy citizen_read_own on public.complaints for select to authenticated
  using (organization_id = (select app.org_id()) and citizen_id = (select auth.uid()));

-- ============================================================================
-- 0006_indicators.sql
-- ============================================================================
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

-- ============================================================================
-- 0007_dashboard_queries.sql
-- ============================================================================
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

-- ============================================================================
-- 0008_mumbai_data.sql
-- ============================================================================
-- CivicOS 0008: published data for Mumbai. GENERATED by data/mumbai/build_sql.py - do not edit by hand.
--
-- Ward boundaries: DataMeet "Municipal Spatial Data", Mumbai BMC wards, CC BY-SA 2.5 India
--   https://github.com/datameet/Municipal_Spatial_Data/tree/master/Mumbai  (simplified to about 25 m)
-- Statistics: Praja Foundation reports (BMC data obtained under the RTI Act and from BMC's Environment
--   Status Report). Every row carries the report, table and PDF page it was read from.
-- No value in this file is estimated, interpolated or generated.

create or replace function app.load_mumbai_data(p_org uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
declare
  v_city uuid;
begin
  if not exists (select 1 from organizations where id = p_org) then
    raise exception 'Unknown organization %', p_org;
  end if;

  -- re-running replaces the previous load
  delete from civic_indicators where organization_id = p_org;
  delete from data_sources     where organization_id = p_org;
  delete from health_index_snapshots where organization_id = p_org;
  delete from cities where organization_id = p_org and name = 'Mumbai';

  insert into cities (organization_id, name, state, is_synthetic_geometry)
  values (p_org, 'Mumbai', 'Maharashtra', false) returning id into v_city;

  insert into city_zones (organization_id, city_id, name, code, boundary, is_synthetic_geometry)
  select p_org, v_city, 'Ward ' || w.code, w.code,
         st_multi(st_setsrid(st_geomfromgeojson(w.geojson), 4326)), false
    from (values
      ('A', '{"type":"MultiPolygon","coordinates":[[[[72.83776,18.94907],[72.84231,18.94894],[72.84681,18.94803],[72.84366,18.93552],[72.84345,18.93539],[72.84325,18.93561],[72.84295,18.93557],[72.84424,18.92901],[72.84299,18.92894],[72.84227,18.93311],[72.84126,18.93337],[72.84001,18.93276],[72.84027,18.93093],[72.83753,18.92898],[72.83694,18.92939],[72.83721,18.92872],[72.83624,18.92813],[72.83686,18.9273],[72.83794,18.92772],[72.8384,18.92678],[72.8404,18.92768],[72.83789,18.92647],[72.84043,18.92125],[72.84432,18.92526],[72.84469,18.92613],[72.84464,18.92528],[72.84032,18.92068],[72.83952,18.92025],[72.8381,18.92042],[72.83487,18.9236],[72.83426,18.92315],[72.83495,18.92292],[72.83466,18.92227],[72.83491,18.92196],[72.8345,18.92164],[72.83365,18.9218],[72.83208,18.91837],[72.83283,18.91811],[72.83206,18.91812],[72.83186,18.91736],[72.82984,18.91602],[72.8302,18.91539],[72.83126,18.91504],[72.82942,18.9129],[72.82693,18.9112],[72.82683,18.91038],[72.82503,18.90734],[72.8223,18.91025],[72.81965,18.90716],[72.8186,18.90645],[72.81787,18.90706],[72.81737,18.90525],[72.81784,18.90432],[72.81745,18.903],[72.81795,18.90274],[72.81743,18.90232],[72.81878,18.90229],[72.81747,18.90225],[72.81727,18.9006],[72.81326,18.89527],[72.81247,18.89492],[72.81097,18.89519],[72.80988,18.894],[72.80915,18.89412],[72.80577,18.89726],[72.80419,18.90043],[72.80356,18.90565],[72.80485,18.91021],[72.81028,18.91738],[72.81804,18.92551],[72.82195,18.93025],[72.8234,18.9336],[72.82387,18.93581],[72.82398,18.93843],[72.82355,18.94146],[72.82882,18.94329],[72.83089,18.94539],[72.83488,18.94842],[72.83776,18.94907]]]]}'),
      ('B', '{"type":"MultiPolygon","coordinates":[[[[72.84456,18.96342],[72.84761,18.96345],[72.84767,18.96375],[72.84938,18.9634],[72.848,18.95796],[72.84961,18.95738],[72.85058,18.95791],[72.85078,18.9588],[72.85106,18.95876],[72.85082,18.95774],[72.84981,18.95727],[72.84952,18.95587],[72.8491,18.95596],[72.84944,18.9573],[72.84795,18.95777],[72.84633,18.95201],[72.84669,18.95195],[72.84619,18.95057],[72.8465,18.95044],[72.84681,18.94803],[72.84231,18.94894],[72.83776,18.94907],[72.83496,18.94846],[72.83366,18.94747],[72.83177,18.95393],[72.83219,18.95505],[72.83175,18.95944],[72.83199,18.96187],[72.83738,18.96259],[72.83882,18.96511],[72.83944,18.96447],[72.84456,18.96342]]]]}'),
      ('C', '{"type":"MultiPolygon","coordinates":[[[[72.83198,18.96174],[72.83175,18.95944],[72.83219,18.95505],[72.83177,18.95393],[72.83366,18.94747],[72.82882,18.94329],[72.82355,18.94146],[72.82172,18.94573],[72.81892,18.94946],[72.82026,18.95065],[72.82542,18.95314],[72.8251,18.95446],[72.82562,18.95503],[72.82503,18.95566],[72.82616,18.95817],[72.82625,18.96169],[72.83198,18.96174]]]]}'),
      ('D', '{"type":"MultiPolygon","coordinates":[[[[72.81873,18.96901],[72.82258,18.96862],[72.82522,18.9679],[72.82449,18.96176],[72.82625,18.96169],[72.82616,18.95817],[72.82503,18.95566],[72.82562,18.95503],[72.8251,18.95446],[72.82542,18.95314],[72.82026,18.95065],[72.81892,18.94946],[72.8177,18.95083],[72.81386,18.95346],[72.81058,18.9547],[72.80808,18.95496],[72.8067,18.95338],[72.80743,18.95323],[72.80553,18.95222],[72.80471,18.95123],[72.80445,18.95146],[72.80418,18.95075],[72.80226,18.94888],[72.80126,18.94828],[72.80034,18.9483],[72.79913,18.9474],[72.79808,18.94746],[72.79768,18.94613],[72.79556,18.94381],[72.7952,18.94169],[72.79422,18.93966],[72.79478,18.9397],[72.7933,18.93921],[72.79267,18.93958],[72.79244,18.94007],[72.79338,18.94195],[72.79349,18.94347],[72.79337,18.94425],[72.79205,18.9457],[72.79156,18.94888],[72.79189,18.94891],[72.79441,18.95447],[72.79941,18.96251],[72.80178,18.97254],[72.80583,18.97929],[72.80778,18.97831],[72.80871,18.97825],[72.80926,18.97883],[72.80961,18.97827],[72.8116,18.97805],[72.82319,18.98037],[72.81873,18.96901]]]]}'),
      ('E', '{"type":"MultiPolygon","coordinates":[[[[72.84677,18.98183],[72.84658,18.98143],[72.85025,18.97995],[72.85005,18.97896],[72.85566,18.97781],[72.85536,18.97667],[72.84984,18.97782],[72.84956,18.97755],[72.8495,18.97646],[72.8512,18.97612],[72.85147,18.97656],[72.8559,18.97566],[72.8559,18.97538],[72.85541,18.97455],[72.85104,18.97549],[72.8509,18.975],[72.84944,18.97528],[72.84933,18.97481],[72.8542,18.97379],[72.85368,18.97203],[72.85133,18.97232],[72.84973,18.97304],[72.85009,18.97226],[72.84987,18.97149],[72.85076,18.97002],[72.853,18.96972],[72.85298,18.96929],[72.85072,18.96944],[72.85136,18.96876],[72.85215,18.96872],[72.8523,18.96781],[72.85141,18.96783],[72.85119,18.96702],[72.85038,18.96716],[72.85041,18.96634],[72.84983,18.96634],[72.85005,18.96599],[72.84938,18.9634],[72.84767,18.96375],[72.84761,18.96345],[72.84662,18.96366],[72.8453,18.96328],[72.83944,18.96447],[72.83882,18.96511],[72.83732,18.96257],[72.83211,18.96188],[72.82449,18.96176],[72.8252,18.96794],[72.82258,18.96862],[72.81858,18.96902],[72.82319,18.98037],[72.82706,18.98142],[72.83312,18.98812],[72.83529,18.9885],[72.84138,18.98813],[72.84261,18.98318],[72.84413,18.98295],[72.84677,18.98183]]]]}'),
      ('F/N', '{"type":"MultiPolygon","coordinates":[[[[72.87091,19.05119],[72.87199,19.04995],[72.8737,19.0499],[72.87595,19.04885],[72.87668,19.04902],[72.87812,19.04786],[72.87935,19.04774],[72.87999,19.04691],[72.87979,19.04563],[72.88073,19.04212],[72.88133,19.03687],[72.88084,19.03474],[72.87813,19.02866],[72.8773,19.02387],[72.87808,19.02177],[72.87986,19.0194],[72.88386,19.0158],[72.88538,19.00794],[72.88088,19.01153],[72.87937,19.01166],[72.87763,19.01135],[72.87251,19.00855],[72.86979,19.00766],[72.86942,19.00867],[72.86902,19.00853],[72.86874,19.00998],[72.86795,19.01042],[72.86619,19.01259],[72.86531,19.01293],[72.86379,19.01516],[72.8631,19.01492],[72.86319,19.01529],[72.8563,19.01053],[72.84748,19.01318],[72.84284,19.01697],[72.86753,19.05258],[72.86889,19.05141],[72.87091,19.05119]]]]}'),
      ('F/S', '{"type":"MultiPolygon","coordinates":[[[[72.85625,19.01059],[72.86319,19.01529],[72.8631,19.01492],[72.86379,19.01516],[72.86531,19.01293],[72.86619,19.01259],[72.86795,19.01042],[72.86863,19.01012],[72.86902,19.00853],[72.86942,19.00867],[72.86979,19.00766],[72.86154,19.00308],[72.86236,19.00302],[72.86141,19.00304],[72.86132,19.00247],[72.8624,19.00229],[72.86234,19.00194],[72.86103,19.00217],[72.85994,18.9984],[72.86096,18.99594],[72.86204,18.99552],[72.86102,18.99578],[72.86162,18.9943],[72.85958,18.99355],[72.85995,18.99276],[72.8569,18.99177],[72.86119,18.98163],[72.85768,18.97837],[72.84976,18.9801],[72.84658,18.98143],[72.84665,18.98189],[72.84261,18.98318],[72.84138,18.98813],[72.83529,18.9885],[72.83313,18.98812],[72.83302,18.98949],[72.8331,18.99834],[72.8342,19.00291],[72.83595,19.00676],[72.84284,19.01697],[72.84748,19.01318],[72.85625,19.01059]]]]}'),
      ('G/N', '{"type":"MultiPolygon","coordinates":[[[[72.86006,19.05228],[72.86738,19.05237],[72.83636,19.0074],[72.83316,19.00933],[72.82928,19.01632],[72.82866,19.01637],[72.82689,19.01942],[72.83073,19.02228],[72.83343,19.02505],[72.83493,19.02736],[72.83729,19.03285],[72.83802,19.03728],[72.83727,19.04406],[72.83623,19.0469],[72.83654,19.04791],[72.83845,19.04832],[72.84216,19.05095],[72.86006,19.05228]]]]}'),
      ('G/S', '{"type":"MultiPolygon","coordinates":[[[[72.82689,19.01942],[72.82866,19.01637],[72.82928,19.01632],[72.83316,19.00933],[72.83636,19.0074],[72.8347,19.00423],[72.83334,18.9999],[72.83302,18.9964],[72.83313,18.98812],[72.82636,18.98101],[72.81171,18.97806],[72.80961,18.97827],[72.80926,18.97883],[72.80853,18.9782],[72.80739,18.97847],[72.80583,18.97929],[72.80941,18.98546],[72.81185,18.99318],[72.81187,18.99605],[72.81127,18.99818],[72.81139,19.00156],[72.81324,19.00489],[72.81443,19.00849],[72.81671,19.01306],[72.81582,19.01626],[72.81533,19.02402],[72.81403,19.02668],[72.81464,19.02688],[72.81737,19.02399],[72.81889,19.02288],[72.81925,19.02307],[72.81858,19.0221],[72.81895,19.0195],[72.8209,19.01782],[72.82274,19.01757],[72.82389,19.01783],[72.82689,19.01942]]]]}'),
      ('H/E', '{"type":"MultiPolygon","coordinates":[[[[72.85932,19.084],[72.85846,19.08204],[72.85882,19.08208],[72.8598,19.08387],[72.8604,19.08375],[72.86128,19.08201],[72.86216,19.08168],[72.86419,19.08243],[72.86492,19.08365],[72.86643,19.08245],[72.86851,19.08246],[72.87593,19.07893],[72.87493,19.0775],[72.87113,19.07568],[72.87213,19.07245],[72.87255,19.07169],[72.87336,19.07134],[72.87251,19.06686],[72.87293,19.06378],[72.87139,19.06155],[72.87128,19.06051],[72.86952,19.0574],[72.86356,19.05233],[72.84322,19.05103],[72.8414,19.05636],[72.84089,19.07149],[72.84137,19.08045],[72.84281,19.09042],[72.84376,19.09068],[72.84588,19.08975],[72.8462,19.08922],[72.8479,19.08942],[72.84939,19.08882],[72.8522,19.0912],[72.85611,19.09266],[72.85787,19.09443],[72.86034,19.09305],[72.8577,19.08874],[72.85918,19.08843],[72.85916,19.08792],[72.85975,19.08737],[72.85932,19.084]]]]}'),
      ('H/W', '{"type":"MultiPolygon","coordinates":[[[[72.84281,19.09042],[72.84137,19.08045],[72.84089,19.07149],[72.8414,19.05636],[72.84322,19.05103],[72.84216,19.05095],[72.83804,19.04821],[72.838,19.04892],[72.83743,19.04932],[72.83644,19.04904],[72.83539,19.04949],[72.83377,19.04942],[72.83234,19.0486],[72.82976,19.04605],[72.82931,19.04492],[72.82321,19.04203],[72.82306,19.04107],[72.82248,19.04113],[72.82251,19.04029],[72.82199,19.04068],[72.8218,19.04168],[72.81924,19.04086],[72.8184,19.04179],[72.81808,19.04168],[72.81771,19.04285],[72.8172,19.04299],[72.8174,19.04415],[72.81864,19.04557],[72.82105,19.05033],[72.82195,19.05352],[72.82353,19.055],[72.82374,19.05593],[72.82318,19.05601],[72.82294,19.05714],[72.82231,19.0573],[72.82053,19.05898],[72.82274,19.06458],[72.82212,19.06767],[72.82239,19.06952],[72.82126,19.07385],[72.82187,19.07483],[72.82151,19.07729],[72.82342,19.07927],[72.82267,19.08205],[72.8231,19.08243],[72.82399,19.08104],[72.82588,19.0799],[72.8278,19.08108],[72.82835,19.08236],[72.82979,19.08371],[72.83041,19.08536],[72.8322,19.08483],[72.83252,19.08637],[72.83812,19.08668],[72.83827,19.08972],[72.84155,19.09057],[72.84281,19.09042]]]]}'),
      ('K/E', '{"type":"MultiPolygon","coordinates":[[[[72.85272,19.14252],[72.85431,19.1425],[72.85705,19.14161],[72.86251,19.14196],[72.86388,19.1413],[72.87538,19.13854],[72.87445,19.13839],[72.87472,19.13758],[72.87596,19.13781],[72.87656,19.13873],[72.87781,19.13879],[72.87833,19.13957],[72.87883,19.13796],[72.88525,19.13685],[72.88558,19.13758],[72.89069,19.13565],[72.88859,19.13221],[72.88871,19.13121],[72.8864,19.12943],[72.88477,19.12954],[72.88474,19.12834],[72.88648,19.12712],[72.88753,19.12279],[72.88859,19.12192],[72.88852,19.12149],[72.88663,19.12067],[72.88585,19.11863],[72.88616,19.11607],[72.88732,19.11406],[72.88527,19.11163],[72.88536,19.11102],[72.88696,19.10984],[72.88706,19.10925],[72.88634,19.10724],[72.88411,19.10554],[72.88364,19.10382],[72.88036,19.10241],[72.87913,19.09975],[72.87909,19.09855],[72.88068,19.09804],[72.88095,19.09665],[72.87974,19.09479],[72.8787,19.09426],[72.87829,19.09329],[72.87872,19.09088],[72.87924,19.09034],[72.87876,19.08845],[72.87916,19.08598],[72.87626,19.08617],[72.876,19.08475],[72.87012,19.08173],[72.86832,19.08251],[72.86643,19.08245],[72.86492,19.08365],[72.86419,19.08243],[72.86294,19.08181],[72.86169,19.08176],[72.86069,19.08279],[72.8604,19.08375],[72.85989,19.08388],[72.85882,19.08208],[72.85846,19.08204],[72.85931,19.08393],[72.85975,19.08737],[72.85916,19.08792],[72.85918,19.08843],[72.8577,19.08874],[72.86034,19.09305],[72.85787,19.09443],[72.85611,19.09266],[72.8522,19.0912],[72.84939,19.08882],[72.8479,19.08942],[72.8462,19.08922],[72.84588,19.08975],[72.84376,19.09068],[72.84281,19.09042],[72.84998,19.14356],[72.85251,19.14327],[72.85272,19.14252]]]]}'),
      ('K/W', '{"type":"MultiPolygon","coordinates":[[[[72.78284,19.13257],[72.78138,19.13261],[72.78042,19.13369],[72.78047,19.1345],[72.78152,19.13525],[72.78313,19.13454],[72.78357,19.13359],[72.78284,19.13257]]],[[[72.82035,19.1557],[72.82201,19.15051],[72.82799,19.15396],[72.8329,19.15129],[72.83945,19.15087],[72.84036,19.14986],[72.8434,19.1502],[72.84441,19.14951],[72.84549,19.14763],[72.84629,19.14707],[72.84593,19.14658],[72.84801,19.14578],[72.84847,19.14464],[72.84836,19.14384],[72.84998,19.14356],[72.84281,19.09042],[72.84155,19.09057],[72.83827,19.08972],[72.83812,19.08668],[72.83252,19.08637],[72.8322,19.08483],[72.83041,19.08536],[72.82979,19.08371],[72.82835,19.08236],[72.8278,19.08108],[72.82588,19.0799],[72.82399,19.08104],[72.82309,19.08244],[72.82339,19.08369],[72.82414,19.08404],[72.82563,19.08714],[72.82654,19.09027],[72.82627,19.09639],[72.82415,19.1029],[72.82285,19.10987],[72.82139,19.11482],[72.81911,19.11992],[72.81305,19.12986],[72.81014,19.13362],[72.8052,19.13883],[72.79485,19.13292],[72.79516,19.13162],[72.79299,19.1307],[72.79181,19.13134],[72.78962,19.13113],[72.78814,19.12988],[72.7872,19.13006],[72.78803,19.13043],[72.78766,19.13266],[72.7883,19.13484],[72.78855,19.13928],[72.78813,19.14026],[72.7882,19.14162],[72.78768,19.14212],[72.78865,19.14466],[72.79145,19.14488],[72.79607,19.14201],[72.79814,19.14285],[72.79821,19.13973],[72.80128,19.13863],[72.80602,19.14995],[72.81104,19.156],[72.81375,19.15326],[72.81823,19.15653],[72.82035,19.1557]]]]}'),
      ('L', '{"type":"MultiPolygon","coordinates":[[[[72.90801,19.10814],[72.90672,19.10707],[72.90501,19.1046],[72.9046,19.10328],[72.90199,19.1014],[72.90059,19.09945],[72.89969,19.09899],[72.89876,19.09602],[72.89934,19.09577],[72.89958,19.09382],[72.89674,19.09163],[72.89594,19.09158],[72.8957,19.09213],[72.89497,19.09228],[72.89489,19.09122],[72.89434,19.09103],[72.89442,19.08572],[72.89267,19.08508],[72.89375,19.08335],[72.89387,19.08098],[72.89145,19.07241],[72.89106,19.06843],[72.89271,19.06817],[72.87835,19.04797],[72.87754,19.04819],[72.87668,19.04902],[72.87595,19.04885],[72.8737,19.0499],[72.87199,19.04995],[72.87103,19.05113],[72.86889,19.05141],[72.86753,19.05258],[72.86356,19.05233],[72.86952,19.0574],[72.87304,19.06422],[72.87248,19.06624],[72.87336,19.07134],[72.87255,19.07169],[72.87213,19.07245],[72.87113,19.07568],[72.87493,19.0775],[72.87593,19.07893],[72.87011,19.08171],[72.876,19.08475],[72.87626,19.08617],[72.87916,19.08598],[72.87876,19.08845],[72.87924,19.09034],[72.87872,19.09088],[72.87829,19.09329],[72.8787,19.09426],[72.87974,19.09479],[72.88095,19.09665],[72.88068,19.09804],[72.87909,19.09855],[72.87913,19.09975],[72.88036,19.10241],[72.88364,19.10382],[72.88411,19.10554],[72.88634,19.10724],[72.88702,19.10909],[72.88696,19.10984],[72.88536,19.11102],[72.88527,19.11163],[72.88732,19.11406],[72.88616,19.11607],[72.88585,19.11863],[72.88663,19.12067],[72.88852,19.12149],[72.88859,19.12192],[72.88753,19.12279],[72.88648,19.12712],[72.88516,19.12777],[72.88489,19.12868],[72.88641,19.12918],[72.89187,19.1255],[72.89573,19.12455],[72.89609,19.12096],[72.90327,19.1175],[72.90449,19.11527],[72.90455,19.11199],[72.90671,19.11096],[72.90801,19.10814]]]]}'),
      ('M/E', '{"type":"MultiPolygon","coordinates":[[[[72.93491,19.07116],[72.93881,19.06464],[72.94134,19.06142],[72.9423,19.05673],[72.94271,19.05648],[72.94363,19.05644],[72.94925,19.05883],[72.95192,19.0621],[72.95371,19.06339],[72.95644,19.06348],[72.95765,19.06304],[72.95947,19.06155],[72.96024,19.0602],[72.9606,19.05688],[72.9595,19.04911],[72.9598,19.04808],[72.95834,19.04419],[72.9567,19.04176],[72.95352,19.03834],[72.95485,19.03751],[72.95396,19.03636],[72.95287,19.03572],[72.95156,19.03097],[72.95112,19.03049],[72.94808,19.02871],[72.93851,19.02479],[72.93717,19.0265],[72.93532,19.02617],[72.93352,19.02531],[72.93251,19.02284],[72.931,19.0217],[72.92695,19.01649],[72.92706,19.01547],[72.92061,19.00714],[72.91801,19.0029],[72.91295,18.9974],[72.9102,18.99608],[72.90737,18.99577],[72.90445,18.99399],[72.90432,19.00297],[72.90491,19.00313],[72.90539,19.00677],[72.90105,19.00792],[72.89998,19.00879],[72.89847,19.00933],[72.89768,19.02749],[72.89513,19.03632],[72.89471,19.03937],[72.89389,19.04094],[72.89519,19.04142],[72.89528,19.04265],[72.89605,19.0424],[72.89656,19.04379],[72.89875,19.04466],[72.89883,19.04609],[72.90934,19.04571],[72.91108,19.05517],[72.91237,19.05723],[72.90773,19.05973],[72.908,19.06002],[72.90757,19.0603],[72.91156,19.06502],[72.91641,19.06654],[72.91918,19.06793],[72.91976,19.06857],[72.92101,19.07377],[72.92222,19.07506],[72.92567,19.07601],[72.92915,19.07549],[72.93491,19.07116]]]]}'),
      ('M/W', '{"type":"MultiPolygon","coordinates":[[[[72.90277,19.07363],[72.90522,19.07158],[72.9073,19.07196],[72.90768,19.07035],[72.90925,19.0704],[72.91179,19.06494],[72.90757,19.0603],[72.908,19.06002],[72.90773,19.05973],[72.91237,19.05723],[72.91108,19.05517],[72.90934,19.04571],[72.89883,19.04609],[72.89875,19.04466],[72.89656,19.04379],[72.89605,19.0424],[72.89528,19.04265],[72.89519,19.04142],[72.89389,19.04094],[72.89471,19.03937],[72.89513,19.03632],[72.89768,19.02749],[72.89847,19.00933],[72.89998,19.00879],[72.90105,19.00792],[72.90539,19.00677],[72.90491,19.00313],[72.90432,19.00297],[72.90445,18.99399],[72.90035,18.99521],[72.89582,18.99521],[72.89128,18.99433],[72.8876,18.99165],[72.88705,18.99244],[72.88646,19.00111],[72.88405,19.01536],[72.87955,19.01979],[72.87808,19.02177],[72.8773,19.02387],[72.87813,19.02866],[72.88084,19.03474],[72.88138,19.03752],[72.88073,19.04212],[72.87979,19.04563],[72.87999,19.04691],[72.87932,19.04776],[72.87823,19.04782],[72.89518,19.07154],[72.8979,19.07203],[72.89923,19.07185],[72.90193,19.07298],[72.90227,19.07277],[72.90277,19.07363]]]]}'),
      ('N', '{"type":"MultiPolygon","coordinates":[[[[72.91762,19.11058],[72.91551,19.10761],[72.9161,19.10631],[72.91591,19.10503],[72.91995,19.10242],[72.9255,19.11075],[72.92677,19.11107],[72.93317,19.10881],[72.93407,19.11078],[72.93462,19.11087],[72.93634,19.11308],[72.94293,19.11476],[72.94614,19.1083],[72.94772,19.1037],[72.94792,19.09205],[72.94906,19.08848],[72.94915,19.08403],[72.9501,19.08233],[72.95115,19.07887],[72.95275,19.07699],[72.95448,19.07257],[72.95438,19.06913],[72.95639,19.06553],[72.95634,19.0635],[72.95371,19.06339],[72.95192,19.0621],[72.94925,19.05883],[72.94363,19.05644],[72.94271,19.05648],[72.9423,19.05673],[72.94134,19.06142],[72.93881,19.06464],[72.93576,19.07011],[72.93324,19.07266],[72.93059,19.07459],[72.92915,19.07549],[72.92711,19.07597],[72.92444,19.07588],[72.92152,19.07456],[72.92101,19.07377],[72.91976,19.06857],[72.91918,19.06793],[72.91303,19.06532],[72.91174,19.0651],[72.90925,19.0704],[72.90768,19.07035],[72.9073,19.07196],[72.90522,19.07158],[72.90286,19.07364],[72.90227,19.07277],[72.90193,19.07298],[72.89923,19.07185],[72.8979,19.07203],[72.89525,19.07158],[72.89271,19.06817],[72.89106,19.06843],[72.89145,19.07241],[72.89387,19.08098],[72.89375,19.08335],[72.89267,19.08508],[72.89442,19.08572],[72.89434,19.09103],[72.89489,19.09122],[72.89497,19.09228],[72.8957,19.09213],[72.89594,19.09158],[72.89674,19.09163],[72.89917,19.09335],[72.8997,19.09455],[72.89934,19.09577],[72.89876,19.09602],[72.89969,19.09899],[72.90059,19.09945],[72.90199,19.1014],[72.9046,19.10328],[72.90501,19.1046],[72.90679,19.10717],[72.90835,19.10841],[72.90978,19.10863],[72.9133,19.11065],[72.91409,19.11181],[72.91521,19.11516],[72.91635,19.1155],[72.9183,19.11705],[72.91846,19.11081],[72.91762,19.11058]]]]}'),
      ('P/N', '{"type":"MultiPolygon","coordinates":[[[[72.79596,19.22451],[72.79839,19.22446],[72.80407,19.22272],[72.80659,19.22108],[72.80717,19.21934],[72.80603,19.2172],[72.80439,19.21678],[72.80339,19.2135],[72.80792,19.21194],[72.8089,19.21077],[72.8086,19.20969],[72.80941,19.20862],[72.81044,19.2086],[72.81039,19.20806],[72.81107,19.20826],[72.81092,19.2065],[72.81432,19.2048],[72.81599,19.20443],[72.82283,19.20499],[72.82301,19.20451],[72.82743,19.20159],[72.82857,19.19962],[72.82939,19.19925],[72.82911,19.1977],[72.83065,19.19626],[72.83186,19.19822],[72.83189,19.19919],[72.83288,19.19918],[72.83593,19.201],[72.83976,19.20043],[72.84259,19.19939],[72.84451,19.19638],[72.8451,19.19644],[72.84523,19.19538],[72.84673,19.19546],[72.84753,19.19492],[72.85055,19.19482],[72.85116,19.19893],[72.85368,19.1989],[72.8541,19.19589],[72.8536,19.19574],[72.85365,19.19391],[72.8551,19.1937],[72.8563,19.19434],[72.86034,19.19468],[72.85982,19.19341],[72.86128,19.19169],[72.86404,19.19098],[72.86476,19.19343],[72.86804,19.19394],[72.86958,19.1937],[72.87299,19.19401],[72.87429,19.19392],[72.87459,19.19348],[72.87671,19.19286],[72.88708,19.19248],[72.89108,19.19119],[72.89568,19.19054],[72.89739,19.1892],[72.90019,19.1851],[72.90027,19.17993],[72.89933,19.17609],[72.89705,19.1736],[72.89234,19.16388],[72.88929,19.16257],[72.88205,19.16454],[72.87682,19.16708],[72.87461,19.17047],[72.87403,19.17597],[72.869,19.17556],[72.86669,19.17584],[72.85947,19.17436],[72.85938,19.1754],[72.85787,19.17536],[72.85721,19.1758],[72.85705,19.17723],[72.8567,19.17748],[72.85142,19.17628],[72.8505,19.17642],[72.84856,19.17775],[72.84628,19.17811],[72.8448,19.17888],[72.83763,19.17933],[72.83678,19.17976],[72.83494,19.17873],[72.82964,19.17849],[72.8293,19.17642],[72.8287,19.17541],[72.82723,19.17441],[72.82576,19.17266],[72.82503,19.16963],[72.81091,19.15586],[72.80602,19.14995],[72.80128,19.13863],[72.79821,19.13973],[72.79814,19.14285],[72.79607,19.14201],[72.79145,19.14488],[72.78865,19.14466],[72.78914,19.14712],[72.78873,19.14975],[72.78714,19.15248],[72.78447,19.15439],[72.78377,19.15736],[72.78265,19.15794],[72.78172,19.1579],[72.78233,19.15901],[72.78356,19.15948],[72.78375,19.16067],[72.78319,19.16208],[72.78141,19.16382],[72.78107,19.16479],[72.78185,19.16713],[72.78401,19.16698],[72.78488,19.16632],[72.78613,19.16654],[72.78736,19.16769],[72.78864,19.16984],[72.79052,19.17101],[72.79316,19.17185],[72.79606,19.18002],[72.79574,19.1833],[72.79622,19.18754],[72.79539,19.19072],[72.79655,19.19362],[72.79656,19.19488],[72.7964,19.19617],[72.79295,19.19559],[72.79128,19.19351],[72.78974,19.19311],[72.78762,19.194],[72.78394,19.19323],[72.78167,19.19455],[72.78265,19.19989],[72.78332,19.20072],[72.78496,19.20075],[72.78584,19.20288],[72.78542,19.20445],[72.78376,19.20622],[72.78203,19.20677],[72.78051,19.20618],[72.78008,19.20642],[72.78037,19.21023],[72.78127,19.21195],[72.78153,19.21395],[72.78147,19.21527],[72.78029,19.21793],[72.78103,19.21853],[72.78023,19.21909],[72.78011,19.21967],[72.78143,19.2202],[72.78101,19.22281],[72.7819,19.22331],[72.78217,19.22424],[72.78294,19.22467],[72.79482,19.22561],[72.79596,19.22451]]]]}'),
      ('P/S', '{"type":"MultiPolygon","coordinates":[[[[72.8377,19.17933],[72.8448,19.17888],[72.84628,19.17811],[72.84856,19.17775],[72.8505,19.17642],[72.85142,19.17628],[72.85676,19.17747],[72.85721,19.1758],[72.85787,19.17536],[72.85938,19.1754],[72.85947,19.17436],[72.86669,19.17584],[72.869,19.17556],[72.87403,19.17597],[72.87461,19.17047],[72.87621,19.16775],[72.87742,19.16662],[72.88205,19.16454],[72.8887,19.1626],[72.89037,19.16284],[72.89234,19.16388],[72.89248,19.16318],[72.89155,19.16027],[72.89047,19.15989],[72.89046,19.15763],[72.88941,19.15685],[72.8935,19.15371],[72.89298,19.15068],[72.89499,19.1473],[72.89528,19.1449],[72.89414,19.142],[72.89333,19.14211],[72.89448,19.13949],[72.89378,19.13799],[72.89197,19.13641],[72.89093,19.13615],[72.8907,19.13561],[72.88558,19.13758],[72.88525,19.13685],[72.87883,19.13796],[72.87833,19.13957],[72.87781,19.13879],[72.87656,19.13873],[72.87596,19.13781],[72.87472,19.13758],[72.87445,19.13839],[72.87538,19.13854],[72.86388,19.1413],[72.86251,19.14196],[72.85705,19.14161],[72.85431,19.1425],[72.85274,19.14248],[72.85251,19.14327],[72.84836,19.14384],[72.84847,19.14464],[72.84801,19.14578],[72.84593,19.14658],[72.84629,19.14707],[72.84549,19.14763],[72.84441,19.14951],[72.84332,19.15023],[72.84036,19.14986],[72.83945,19.15087],[72.8329,19.15129],[72.82799,19.15396],[72.82201,19.15051],[72.82097,19.15438],[72.81985,19.156],[72.81823,19.15653],[72.81375,19.15326],[72.81104,19.156],[72.82503,19.16963],[72.82576,19.17266],[72.82723,19.17441],[72.8287,19.17541],[72.8293,19.17642],[72.82964,19.17849],[72.83494,19.17873],[72.83633,19.17975],[72.8377,19.17933]]]]}'),
      ('R/C', '{"type":"MultiPolygon","coordinates":[[[[72.78986,19.26147],[72.79972,19.26227],[72.80089,19.26108],[72.80036,19.2604],[72.80081,19.25882],[72.80166,19.25906],[72.80354,19.25825],[72.80784,19.25499],[72.81483,19.24837],[72.81652,19.24722],[72.81823,19.24669],[72.8272,19.24497],[72.82918,19.24719],[72.83496,19.24952],[72.84417,19.24159],[72.84984,19.23809],[72.85517,19.23777],[72.85799,19.2371],[72.85866,19.23728],[72.85894,19.23876],[72.85979,19.23941],[72.86294,19.23741],[72.86416,19.23724],[72.86435,19.2385],[72.87028,19.23796],[72.87766,19.23898],[72.89358,19.24944],[72.8987,19.24794],[72.90103,19.24145],[72.90879,19.2328],[72.90948,19.22924],[72.91009,19.2287],[72.91097,19.22604],[72.90991,19.21849],[72.90824,19.21687],[72.90745,19.21047],[72.91017,19.2076],[72.90899,19.20247],[72.90099,19.20106],[72.89954,19.20487],[72.89532,19.20763],[72.89534,19.20841],[72.89411,19.20855],[72.89407,19.20829],[72.89201,19.20933],[72.89191,19.21051],[72.89123,19.21072],[72.89023,19.21012],[72.88695,19.21162],[72.88633,19.21588],[72.88206,19.21732],[72.8782,19.21411],[72.87758,19.21445],[72.8692,19.21455],[72.86348,19.21307],[72.85744,19.21289],[72.8536,19.21391],[72.85149,19.21354],[72.85116,19.21386],[72.84824,19.21244],[72.84627,19.21215],[72.8419,19.21312],[72.83826,19.2151],[72.83578,19.21538],[72.82098,19.21561],[72.80361,19.21414],[72.80455,19.21702],[72.80603,19.2172],[72.80717,19.21934],[72.80659,19.22108],[72.80407,19.22272],[72.79839,19.22446],[72.79629,19.22437],[72.79523,19.22488],[72.79482,19.22561],[72.78288,19.22465],[72.78217,19.22424],[72.7819,19.22331],[72.78101,19.22281],[72.78143,19.2202],[72.78021,19.21985],[72.78023,19.21909],[72.78104,19.21847],[72.77998,19.21793],[72.77907,19.21915],[72.77907,19.22045],[72.7783,19.22043],[72.77769,19.22168],[72.77678,19.22215],[72.77633,19.22495],[72.77658,19.22595],[72.77782,19.22653],[72.78064,19.23101],[72.77908,19.23698],[72.78116,19.24047],[72.78101,19.24305],[72.78309,19.25029],[72.78281,19.25544],[72.78169,19.25977],[72.78299,19.26008],[72.78425,19.2621],[72.78452,19.26314],[72.78416,19.26478],[72.78831,19.26321],[72.78986,19.26147]]]]}'),
      ('R/N', '{"type":"MultiPolygon","coordinates":[[[[72.85493,19.26995],[72.85573,19.26957],[72.85681,19.26972],[72.8569,19.26864],[72.85919,19.2682],[72.86118,19.26668],[72.8625,19.26705],[72.86264,19.26779],[72.86465,19.26603],[72.86619,19.26658],[72.86593,19.26466],[72.86885,19.26114],[72.86892,19.262],[72.86936,19.26209],[72.86992,19.26173],[72.86982,19.26061],[72.87011,19.26108],[72.87187,19.26125],[72.87385,19.26058],[72.87611,19.26044],[72.87765,19.25879],[72.87865,19.25681],[72.8818,19.25423],[72.88485,19.25328],[72.88867,19.24986],[72.89358,19.24944],[72.87766,19.23898],[72.87028,19.23796],[72.86435,19.2385],[72.86416,19.23724],[72.86294,19.23741],[72.86101,19.23889],[72.85942,19.23938],[72.85866,19.23728],[72.85799,19.2371],[72.8555,19.23773],[72.84895,19.23838],[72.84192,19.24339],[72.83496,19.24952],[72.8386,19.25204],[72.83617,19.25506],[72.83578,19.25863],[72.83696,19.2634],[72.83873,19.26597],[72.83981,19.26674],[72.84167,19.26742],[72.84556,19.26693],[72.84708,19.26734],[72.85081,19.2699],[72.85493,19.26995]]]]}'),
      ('R/S', '{"type":"MultiPolygon","coordinates":[[[[72.88633,19.21588],[72.88695,19.21162],[72.89023,19.21012],[72.89123,19.21072],[72.89191,19.21051],[72.89201,19.20933],[72.89407,19.20829],[72.89411,19.20855],[72.89534,19.20841],[72.89532,19.20763],[72.89954,19.20487],[72.90099,19.20106],[72.90244,19.20139],[72.90236,19.19725],[72.90147,19.19637],[72.90032,19.19154],[72.90019,19.1851],[72.89739,19.1892],[72.89568,19.19054],[72.89108,19.19119],[72.88708,19.19248],[72.87671,19.19286],[72.87405,19.19396],[72.86804,19.19394],[72.86476,19.19343],[72.86404,19.19098],[72.86146,19.19158],[72.85982,19.19341],[72.86034,19.19468],[72.8563,19.19434],[72.8551,19.1937],[72.85365,19.19391],[72.8536,19.19574],[72.8541,19.19589],[72.85368,19.1989],[72.85116,19.19893],[72.85055,19.19482],[72.84753,19.19492],[72.84673,19.19546],[72.84523,19.19538],[72.8451,19.19644],[72.84451,19.19638],[72.84259,19.19939],[72.83976,19.20043],[72.83593,19.201],[72.83288,19.19918],[72.83189,19.19919],[72.83186,19.19822],[72.83065,19.19626],[72.82911,19.1977],[72.82939,19.19925],[72.82857,19.19962],[72.82743,19.20159],[72.82301,19.20451],[72.82283,19.20499],[72.81663,19.20438],[72.81432,19.2048],[72.81092,19.2065],[72.81107,19.20826],[72.81039,19.20806],[72.81044,19.2086],[72.80941,19.20862],[72.8086,19.20969],[72.8089,19.21077],[72.80792,19.21194],[72.80339,19.2135],[72.80361,19.21414],[72.82098,19.21561],[72.83578,19.21538],[72.83826,19.2151],[72.8419,19.21312],[72.84627,19.21215],[72.84824,19.21244],[72.85116,19.21386],[72.85149,19.21354],[72.8536,19.21391],[72.85744,19.21289],[72.86348,19.21307],[72.8692,19.21455],[72.87758,19.21445],[72.8782,19.21411],[72.88206,19.21732],[72.88633,19.21588]]]]}'),
      ('S', '{"type":"MultiPolygon","coordinates":[[[[72.93134,19.16719],[72.93706,19.16391],[72.93928,19.16362],[72.94642,19.16064],[72.94698,19.15973],[72.94665,19.15772],[72.94731,19.15695],[72.95693,19.15468],[72.95468,19.1513],[72.95624,19.15024],[72.95828,19.15016],[72.96145,19.14866],[72.96187,19.1472],[72.96162,19.14657],[72.95822,19.14457],[72.95701,19.14306],[72.95666,19.14176],[72.95689,19.13935],[72.95969,19.1358],[72.96131,19.13453],[72.95904,19.13231],[72.96121,19.1286],[72.96074,19.12597],[72.95458,19.11691],[72.95374,19.11395],[72.95182,19.11083],[72.94906,19.11135],[72.94537,19.11459],[72.94407,19.11482],[72.93634,19.11308],[72.93462,19.11087],[72.93407,19.11078],[72.93317,19.10881],[72.92677,19.11107],[72.9255,19.11075],[72.91995,19.10242],[72.91591,19.10503],[72.9161,19.10631],[72.9155,19.1074],[72.91762,19.11058],[72.91846,19.11081],[72.9183,19.11705],[72.91635,19.1155],[72.91521,19.11516],[72.91409,19.11181],[72.9133,19.11065],[72.90978,19.10863],[72.90801,19.10814],[72.90671,19.11096],[72.90455,19.11199],[72.90449,19.11527],[72.90327,19.1175],[72.89609,19.12096],[72.89573,19.12455],[72.89208,19.12539],[72.88641,19.12918],[72.88489,19.12868],[72.88477,19.12954],[72.8864,19.12943],[72.88871,19.13121],[72.88859,19.13221],[72.89093,19.13615],[72.89197,19.13641],[72.89378,19.13799],[72.89448,19.13949],[72.89333,19.14211],[72.89442,19.14209],[72.89449,19.14261],[72.8954,19.14263],[72.89637,19.14189],[72.89893,19.14095],[72.89978,19.13935],[72.9002,19.13981],[72.90063,19.13971],[72.90118,19.14064],[72.90196,19.14053],[72.90198,19.14126],[72.90481,19.14097],[72.90478,19.14035],[72.90616,19.13968],[72.90696,19.14026],[72.90736,19.13933],[72.91003,19.14003],[72.91073,19.14059],[72.91183,19.14024],[72.91272,19.14045],[72.91288,19.14117],[72.91354,19.14127],[72.91392,19.14179],[72.91626,19.14131],[72.91813,19.1414],[72.91845,19.14087],[72.92067,19.14406],[72.92164,19.14461],[72.92297,19.1463],[72.92405,19.14953],[72.92405,19.15085],[72.92478,19.15204],[72.92602,19.15311],[72.92672,19.15306],[72.92744,19.15392],[72.9272,19.15546],[72.92803,19.15624],[72.92869,19.15787],[72.92849,19.15926],[72.92898,19.16283],[72.92866,19.16322],[72.92865,19.16533],[72.92902,19.16527],[72.9287,19.16652],[72.93134,19.16719]]]]}'),
      ('T', '{"type":"MultiPolygon","coordinates":[[[[72.93702,19.19183],[72.94194,19.18739],[72.94288,19.18785],[72.94344,19.1876],[72.94502,19.18811],[72.94673,19.18802],[72.94961,19.18708],[72.95008,19.18666],[72.95007,19.18595],[72.95127,19.18506],[72.9533,19.18474],[72.95498,19.18518],[72.95586,19.18422],[72.95579,19.18333],[72.95835,19.18215],[72.95862,19.18081],[72.95956,19.18021],[72.95939,19.17942],[72.9598,19.17893],[72.96106,19.17887],[72.96167,19.17944],[72.96255,19.17843],[72.96256,19.17762],[72.96378,19.17667],[72.96574,19.17714],[72.96697,19.17795],[72.96803,19.17791],[72.96851,19.17601],[72.97022,19.17556],[72.97092,19.17609],[72.97186,19.1787],[72.97268,19.17853],[72.97295,19.17835],[72.9727,19.17731],[72.97357,19.1772],[72.97594,19.17355],[72.97973,19.16888],[72.97683,19.15986],[72.97566,19.15266],[72.97304,19.1493],[72.96807,19.14065],[72.96568,19.13908],[72.96131,19.13453],[72.95939,19.13613],[72.95678,19.13972],[72.95666,19.14176],[72.95716,19.14332],[72.95839,19.1447],[72.96135,19.14629],[72.96187,19.1472],[72.96117,19.14888],[72.95828,19.15016],[72.95624,19.15024],[72.95468,19.1513],[72.95693,19.15468],[72.94723,19.15699],[72.94665,19.15772],[72.94698,19.15973],[72.94642,19.16064],[72.93928,19.16362],[72.93698,19.16394],[72.93098,19.16722],[72.9287,19.16652],[72.92902,19.16527],[72.92865,19.16533],[72.92866,19.16322],[72.92898,19.16283],[72.92849,19.15926],[72.92869,19.15787],[72.92803,19.15624],[72.9272,19.15546],[72.92744,19.15392],[72.92672,19.15306],[72.92602,19.15311],[72.92478,19.15204],[72.92405,19.15085],[72.92405,19.14953],[72.92297,19.1463],[72.92164,19.14461],[72.92067,19.14406],[72.91845,19.14087],[72.91813,19.1414],[72.91626,19.14131],[72.91392,19.14179],[72.91354,19.14127],[72.91288,19.14117],[72.91272,19.14045],[72.91183,19.14024],[72.91073,19.14059],[72.91003,19.14003],[72.90736,19.13933],[72.90696,19.14026],[72.90616,19.13968],[72.90478,19.14035],[72.90481,19.14097],[72.90198,19.14126],[72.90196,19.14053],[72.90118,19.14064],[72.90063,19.13971],[72.9002,19.13981],[72.89978,19.13935],[72.89903,19.14088],[72.89637,19.14189],[72.8954,19.14263],[72.89449,19.14261],[72.89414,19.142],[72.89534,19.14521],[72.89499,19.1473],[72.89298,19.15068],[72.8935,19.15371],[72.88941,19.15685],[72.89046,19.15763],[72.89047,19.15989],[72.89155,19.16027],[72.89248,19.16318],[72.89232,19.16397],[72.89705,19.1736],[72.89933,19.17609],[72.90027,19.17993],[72.89999,19.18326],[72.90032,19.19154],[72.90147,19.19637],[72.90236,19.19725],[72.90244,19.20139],[72.90899,19.20247],[72.91017,19.2076],[72.91346,19.20826],[72.91486,19.21017],[72.91721,19.21617],[72.92009,19.21693],[72.92229,19.21639],[72.92616,19.21352],[72.92757,19.21169],[72.93098,19.21123],[72.93296,19.20711],[72.93551,19.2055],[72.93533,19.194],[72.93702,19.19183]]]]}')
    ) as w(code, geojson);

  insert into data_sources (organization_id, id, publisher, report, table_ref, page, title, url, note) values
    (p_org, 'datameet-wards', 'DataMeet India community', 'Municipal Spatial Data: Mumbai BMC wards', null, null, 'Ward boundaries of the Brihanmumbai Municipal Corporation', 'https://github.com/datameet/Municipal_Spatial_Data/tree/master/Mumbai', 'CC BY-SA 2.5 India. Simplified for display.'),
    (p_org, 'p25-t1', 'Praja Foundation', 'Report on the Status of Civic Issues in Mumbai (2025)', 'Table 1', 12, 'Water Sources, Demand, and Supply Deficit in Mumbai (2023-24), as per the Environmental Status Report', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Issues%20in%20Mumbai.pdf', null),
    (p_org, 'p25-t4', 'Praja Foundation', 'Report on the Status of Civic Issues in Mumbai (2025)', 'Table 4', 14, 'Ward wise Number of zones with water supply duration (2024)', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Issues%20in%20Mumbai.pdf', null),
    (p_org, 'p25-t45', 'Praja Foundation', 'Report on the Status of Civic Issues in Mumbai (2025)', 'Table 45', 73, 'Ward-wise Comparison of Total Complaints and Complaints Closed in 2023 and 2024', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Issues%20in%20Mumbai.pdf', null),
    (p_org, 'p25-t7', 'Praja Foundation', 'Report on the Status of Civic Issues in Mumbai (2025)', 'Table 7', 17, 'Ward Wise Drinking Water Quality Testing Results from 2020 to 2024', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Issues%20in%20Mumbai.pdf', null),
    (p_org, 'p26-t1', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 1', 11, 'Issue Wise Overall Complaints from 2016 to 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null),
    (p_org, 'p26-t11', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 11', 25, 'Ward wise Garbage Lifted from January 2025 to December 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null),
    (p_org, 'p26-t2', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 2', 12, 'Issue-wise Comparison of Total Complaints and Complaints Closed in 2023 and 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null),
    (p_org, 'p26-t29', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 29', 46, 'Average Month-wise AQI from January 2016 to December 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null),
    (p_org, 'p26-t3', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 3', 13, 'Ward-wise Comparison of Total Complaints and Complaints Closed in 2023 and 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null),
    (p_org, 'p26-t30', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 30', 47, 'Ward and Region wise Average Number of Days with Air Quality Level for the Year 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null),
    (p_org, 'p26-t37', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 37', 94, 'Ward wise Waste Generation from Year 2021 to Year 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null),
    (p_org, 'p26-t39', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 39', 96, 'Ward-wise Solid Waste Management Complaints from 2016 to 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null),
    (p_org, 'p26-t40', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 40', 97, 'Ward-wise SWM Complaints Registered, Closed and Average Days for Closure in 2021 and 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null),
    (p_org, 'p26-t41', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 41', 98, 'Ward-wise Drainage Complaints from 2016 to 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null),
    (p_org, 'p26-t42', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 42', 99, 'Ward-wise Drainage Complaints Registered, Closed and Average Days for Closure in 2021 and 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null),
    (p_org, 'p26-t43', 'Praja Foundation', 'Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)', 'Table 43', 100, 'Ward-wise Total Complaints Registered in Civic Complaint System from 2016 to 2025', 'https://praja.org/praja_docs/praja_downloads/Report%20on%20the%20Status%20of%20Civic%20Services,%20Environmental%20and%20Climate%20Issues%20in%20Mumbai%202026.pdf', null);

  insert into civic_indicators (organization_id, zone_id, year, month, metric, category, value, unit, source_id)
  select p_org, z.id, v.year, v.month, v.metric, v.category, v.value, v.unit, v.source_id
    from (values
      (null, 2023, null::int, 'complaints_closed', 'Buildings', 9181::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Buildings', 58::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Buildings', 15332::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Buildings', 47::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Colony Officer', 697::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Colony Officer', 46::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Colony Officer', 499::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Colony Officer', 52::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Drainage', 16509::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Drainage', 28::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Drainage', 15067::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Drainage', 41::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Estate', 279::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Estate', 66::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Estate', 902::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Estate', 45::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Garden', 3582::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Garden', 23::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Garden', 3414::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Garden', 20::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'License', 12410::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'License', 42::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'License', 16072::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'License', 32::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'MCGM Related', 549::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'MCGM Related', 52::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'MCGM Related', 648::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'MCGM Related', 45::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Medical Officer Health (MOH)', 1324::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Medical Officer Health (MOH)', 56::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Medical Officer Health (MOH)', 1608::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Medical Officer Health (MOH)', 41::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Miscellaneous issues in Civic', 1112::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Miscellaneous issues in Civic', 58::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Miscellaneous issues in Civic', 1527::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Miscellaneous issues in Civic', 54::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Pest control', 8230::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Pest control', 16::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Pest control', 10002::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Pest control', 12::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Pollution', 377::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Pollution', 124::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Pollution', 1281::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Pollution', 33::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Roads', 8011::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Roads', 54::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Roads', 10012::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Roads', 49::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'School', 19::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'School', 84::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'School', 35::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'School', 92::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Shop and Establishment', 685::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Shop and Establishment', 23::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Shop and Establishment', 584::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Shop and Establishment', 18::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 23540::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 15::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 26379::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 8::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Storm Water Drainage', 1905::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Storm Water Drainage', 33::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Storm Water Drainage', 2080::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Storm Water Drainage', 45::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Toilet', 503::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Toilet', 25::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Toilet', 626::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Toilet', 18::numeric, 'days', 'p26-t2'),
      (null, 2023, null::int, 'complaints_closed', 'Water Supply', 13999::numeric, 'complaints', 'p26-t2'),
      (null, 2023, null::int, 'avg_days_to_close', 'Water Supply', 29::numeric, 'days', 'p26-t2'),
      (null, 2025, null::int, 'complaints_closed', 'Water Supply', 13390::numeric, 'complaints', 'p26-t2'),
      (null, 2025, null::int, 'avg_days_to_close', 'Water Supply', 32::numeric, 'days', 'p26-t2'),
      ('A', 2016, null::int, 'complaints_registered', null, 1972::numeric, 'complaints', 'p26-t43'),
      ('A', 2017, null::int, 'complaints_registered', null, 1840::numeric, 'complaints', 'p26-t43'),
      ('A', 2018, null::int, 'complaints_registered', null, 2474::numeric, 'complaints', 'p26-t43'),
      ('A', 2019, null::int, 'complaints_registered', null, 2896::numeric, 'complaints', 'p26-t43'),
      ('A', 2020, null::int, 'complaints_registered', null, 1763::numeric, 'complaints', 'p26-t43'),
      ('A', 2021, null::int, 'complaints_registered', null, 1764::numeric, 'complaints', 'p26-t43'),
      ('A', 2022, null::int, 'complaints_registered', null, 2061::numeric, 'complaints', 'p26-t43'),
      ('A', 2023, null::int, 'complaints_registered', null, 2468::numeric, 'complaints', 'p26-t43'),
      ('A', 2024, null::int, 'complaints_registered', null, 3207::numeric, 'complaints', 'p26-t43'),
      ('A', 2025, null::int, 'complaints_registered', null, 1988::numeric, 'complaints', 'p26-t43'),
      ('A', 2025, null::int, 'population', null, 194900::numeric, 'people', 'p26-t43'),
      ('B', 2016, null::int, 'complaints_registered', null, 1916::numeric, 'complaints', 'p26-t43'),
      ('B', 2017, null::int, 'complaints_registered', null, 2341::numeric, 'complaints', 'p26-t43'),
      ('B', 2018, null::int, 'complaints_registered', null, 3972::numeric, 'complaints', 'p26-t43'),
      ('B', 2019, null::int, 'complaints_registered', null, 3959::numeric, 'complaints', 'p26-t43'),
      ('B', 2020, null::int, 'complaints_registered', null, 2461::numeric, 'complaints', 'p26-t43'),
      ('B', 2021, null::int, 'complaints_registered', null, 2901::numeric, 'complaints', 'p26-t43'),
      ('B', 2022, null::int, 'complaints_registered', null, 3047::numeric, 'complaints', 'p26-t43'),
      ('B', 2023, null::int, 'complaints_registered', null, 3324::numeric, 'complaints', 'p26-t43'),
      ('B', 2024, null::int, 'complaints_registered', null, 3019::numeric, 'complaints', 'p26-t43'),
      ('B', 2025, null::int, 'complaints_registered', null, 3045::numeric, 'complaints', 'p26-t43'),
      ('B', 2025, null::int, 'population', null, 134091::numeric, 'people', 'p26-t43'),
      ('C', 2016, null::int, 'complaints_registered', null, 1899::numeric, 'complaints', 'p26-t43'),
      ('C', 2017, null::int, 'complaints_registered', null, 2895::numeric, 'complaints', 'p26-t43'),
      ('C', 2018, null::int, 'complaints_registered', null, 3696::numeric, 'complaints', 'p26-t43'),
      ('C', 2019, null::int, 'complaints_registered', null, 3596::numeric, 'complaints', 'p26-t43'),
      ('C', 2020, null::int, 'complaints_registered', null, 2888::numeric, 'complaints', 'p26-t43'),
      ('C', 2021, null::int, 'complaints_registered', null, 2632::numeric, 'complaints', 'p26-t43'),
      ('C', 2022, null::int, 'complaints_registered', null, 2826::numeric, 'complaints', 'p26-t43'),
      ('C', 2023, null::int, 'complaints_registered', null, 3306::numeric, 'complaints', 'p26-t43'),
      ('C', 2024, null::int, 'complaints_registered', null, 3864::numeric, 'complaints', 'p26-t43'),
      ('C', 2025, null::int, 'complaints_registered', null, 3571::numeric, 'complaints', 'p26-t43'),
      ('C', 2025, null::int, 'population', null, 175039::numeric, 'people', 'p26-t43'),
      ('D', 2016, null::int, 'complaints_registered', null, 4081::numeric, 'complaints', 'p26-t43'),
      ('D', 2017, null::int, 'complaints_registered', null, 4053::numeric, 'complaints', 'p26-t43'),
      ('D', 2018, null::int, 'complaints_registered', null, 4815::numeric, 'complaints', 'p26-t43'),
      ('D', 2019, null::int, 'complaints_registered', null, 5159::numeric, 'complaints', 'p26-t43'),
      ('D', 2020, null::int, 'complaints_registered', null, 3730::numeric, 'complaints', 'p26-t43'),
      ('D', 2021, null::int, 'complaints_registered', null, 3191::numeric, 'complaints', 'p26-t43'),
      ('D', 2022, null::int, 'complaints_registered', null, 3566::numeric, 'complaints', 'p26-t43'),
      ('D', 2023, null::int, 'complaints_registered', null, 4022::numeric, 'complaints', 'p26-t43'),
      ('D', 2024, null::int, 'complaints_registered', null, 3748::numeric, 'complaints', 'p26-t43'),
      ('D', 2025, null::int, 'complaints_registered', null, 3857::numeric, 'complaints', 'p26-t43'),
      ('D', 2025, null::int, 'population', null, 365399::numeric, 'people', 'p26-t43'),
      ('E', 2016, null::int, 'complaints_registered', null, 2992::numeric, 'complaints', 'p26-t43'),
      ('E', 2017, null::int, 'complaints_registered', null, 3183::numeric, 'complaints', 'p26-t43'),
      ('E', 2018, null::int, 'complaints_registered', null, 4337::numeric, 'complaints', 'p26-t43'),
      ('E', 2019, null::int, 'complaints_registered', null, 4642::numeric, 'complaints', 'p26-t43'),
      ('E', 2020, null::int, 'complaints_registered', null, 3660::numeric, 'complaints', 'p26-t43'),
      ('E', 2021, null::int, 'complaints_registered', null, 3438::numeric, 'complaints', 'p26-t43'),
      ('E', 2022, null::int, 'complaints_registered', null, 3792::numeric, 'complaints', 'p26-t43'),
      ('E', 2023, null::int, 'complaints_registered', null, 4178::numeric, 'complaints', 'p26-t43'),
      ('E', 2024, null::int, 'complaints_registered', null, 4939::numeric, 'complaints', 'p26-t43'),
      ('E', 2025, null::int, 'complaints_registered', null, 4391::numeric, 'complaints', 'p26-t43'),
      ('E', 2025, null::int, 'population', null, 414299::numeric, 'people', 'p26-t43'),
      ('F/N', 2016, null::int, 'complaints_registered', null, 2765::numeric, 'complaints', 'p26-t43'),
      ('F/N', 2017, null::int, 'complaints_registered', null, 2944::numeric, 'complaints', 'p26-t43'),
      ('F/N', 2018, null::int, 'complaints_registered', null, 4425::numeric, 'complaints', 'p26-t43'),
      ('F/N', 2019, null::int, 'complaints_registered', null, 5304::numeric, 'complaints', 'p26-t43'),
      ('F/N', 2020, null::int, 'complaints_registered', null, 3597::numeric, 'complaints', 'p26-t43'),
      ('F/N', 2021, null::int, 'complaints_registered', null, 3094::numeric, 'complaints', 'p26-t43'),
      ('F/N', 2022, null::int, 'complaints_registered', null, 3799::numeric, 'complaints', 'p26-t43'),
      ('F/N', 2023, null::int, 'complaints_registered', null, 4672::numeric, 'complaints', 'p26-t43'),
      ('F/N', 2024, null::int, 'complaints_registered', null, 4229::numeric, 'complaints', 'p26-t43'),
      ('F/N', 2025, null::int, 'complaints_registered', null, 4075::numeric, 'complaints', 'p26-t43'),
      ('F/N', 2025, null::int, 'population', null, 557301::numeric, 'people', 'p26-t43'),
      ('F/S', 2016, null::int, 'complaints_registered', null, 1628::numeric, 'complaints', 'p26-t43'),
      ('F/S', 2017, null::int, 'complaints_registered', null, 1624::numeric, 'complaints', 'p26-t43'),
      ('F/S', 2018, null::int, 'complaints_registered', null, 2369::numeric, 'complaints', 'p26-t43'),
      ('F/S', 2019, null::int, 'complaints_registered', null, 2857::numeric, 'complaints', 'p26-t43'),
      ('F/S', 2020, null::int, 'complaints_registered', null, 2444::numeric, 'complaints', 'p26-t43'),
      ('F/S', 2021, null::int, 'complaints_registered', null, 2270::numeric, 'complaints', 'p26-t43'),
      ('F/S', 2022, null::int, 'complaints_registered', null, 3102::numeric, 'complaints', 'p26-t43'),
      ('F/S', 2023, null::int, 'complaints_registered', null, 2742::numeric, 'complaints', 'p26-t43'),
      ('F/S', 2024, null::int, 'complaints_registered', null, 2781::numeric, 'complaints', 'p26-t43'),
      ('F/S', 2025, null::int, 'complaints_registered', null, 2739::numeric, 'complaints', 'p26-t43'),
      ('F/S', 2025, null::int, 'population', null, 380259::numeric, 'people', 'p26-t43'),
      ('G/N', 2016, null::int, 'complaints_registered', null, 4416::numeric, 'complaints', 'p26-t43'),
      ('G/N', 2017, null::int, 'complaints_registered', null, 4840::numeric, 'complaints', 'p26-t43'),
      ('G/N', 2018, null::int, 'complaints_registered', null, 6241::numeric, 'complaints', 'p26-t43'),
      ('G/N', 2019, null::int, 'complaints_registered', null, 5954::numeric, 'complaints', 'p26-t43'),
      ('G/N', 2020, null::int, 'complaints_registered', null, 4657::numeric, 'complaints', 'p26-t43'),
      ('G/N', 2021, null::int, 'complaints_registered', null, 4859::numeric, 'complaints', 'p26-t43'),
      ('G/N', 2022, null::int, 'complaints_registered', null, 5158::numeric, 'complaints', 'p26-t43'),
      ('G/N', 2023, null::int, 'complaints_registered', null, 5545::numeric, 'complaints', 'p26-t43'),
      ('G/N', 2024, null::int, 'complaints_registered', null, 5151::numeric, 'complaints', 'p26-t43'),
      ('G/N', 2025, null::int, 'complaints_registered', null, 4922::numeric, 'complaints', 'p26-t43'),
      ('G/N', 2025, null::int, 'population', null, 631046::numeric, 'people', 'p26-t43'),
      ('G/S', 2016, null::int, 'complaints_registered', null, 1983::numeric, 'complaints', 'p26-t43'),
      ('G/S', 2017, null::int, 'complaints_registered', null, 2471::numeric, 'complaints', 'p26-t43'),
      ('G/S', 2018, null::int, 'complaints_registered', null, 3160::numeric, 'complaints', 'p26-t43'),
      ('G/S', 2019, null::int, 'complaints_registered', null, 4192::numeric, 'complaints', 'p26-t43'),
      ('G/S', 2020, null::int, 'complaints_registered', null, 2658::numeric, 'complaints', 'p26-t43'),
      ('G/S', 2021, null::int, 'complaints_registered', null, 2264::numeric, 'complaints', 'p26-t43'),
      ('G/S', 2022, null::int, 'complaints_registered', null, 2847::numeric, 'complaints', 'p26-t43'),
      ('G/S', 2023, null::int, 'complaints_registered', null, 3134::numeric, 'complaints', 'p26-t43'),
      ('G/S', 2024, null::int, 'complaints_registered', null, 3299::numeric, 'complaints', 'p26-t43'),
      ('G/S', 2025, null::int, 'complaints_registered', null, 3154::numeric, 'complaints', 'p26-t43'),
      ('G/S', 2025, null::int, 'population', null, 397932::numeric, 'people', 'p26-t43'),
      ('H/E', 2016, null::int, 'complaints_registered', null, 2774::numeric, 'complaints', 'p26-t43'),
      ('H/E', 2017, null::int, 'complaints_registered', null, 2937::numeric, 'complaints', 'p26-t43'),
      ('H/E', 2018, null::int, 'complaints_registered', null, 3518::numeric, 'complaints', 'p26-t43'),
      ('H/E', 2019, null::int, 'complaints_registered', null, 4397::numeric, 'complaints', 'p26-t43'),
      ('H/E', 2020, null::int, 'complaints_registered', null, 3519::numeric, 'complaints', 'p26-t43'),
      ('H/E', 2021, null::int, 'complaints_registered', null, 2851::numeric, 'complaints', 'p26-t43'),
      ('H/E', 2022, null::int, 'complaints_registered', null, 3733::numeric, 'complaints', 'p26-t43'),
      ('H/E', 2023, null::int, 'complaints_registered', null, 4414::numeric, 'complaints', 'p26-t43'),
      ('H/E', 2024, null::int, 'complaints_registered', null, 4317::numeric, 'complaints', 'p26-t43'),
      ('H/E', 2025, null::int, 'complaints_registered', null, 3855::numeric, 'complaints', 'p26-t43'),
      ('H/E', 2025, null::int, 'population', null, 587012::numeric, 'people', 'p26-t43'),
      ('H/W', 2016, null::int, 'complaints_registered', null, 3093::numeric, 'complaints', 'p26-t43'),
      ('H/W', 2017, null::int, 'complaints_registered', null, 3430::numeric, 'complaints', 'p26-t43'),
      ('H/W', 2018, null::int, 'complaints_registered', null, 4763::numeric, 'complaints', 'p26-t43'),
      ('H/W', 2019, null::int, 'complaints_registered', null, 4774::numeric, 'complaints', 'p26-t43'),
      ('H/W', 2020, null::int, 'complaints_registered', null, 3481::numeric, 'complaints', 'p26-t43'),
      ('H/W', 2021, null::int, 'complaints_registered', null, 3623::numeric, 'complaints', 'p26-t43'),
      ('H/W', 2022, null::int, 'complaints_registered', null, 4713::numeric, 'complaints', 'p26-t43'),
      ('H/W', 2023, null::int, 'complaints_registered', null, 5199::numeric, 'complaints', 'p26-t43'),
      ('H/W', 2024, null::int, 'complaints_registered', null, 5048::numeric, 'complaints', 'p26-t43'),
      ('H/W', 2025, null::int, 'complaints_registered', null, 4938::numeric, 'complaints', 'p26-t43'),
      ('H/W', 2025, null::int, 'population', null, 324016::numeric, 'people', 'p26-t43'),
      ('K/E', 2016, null::int, 'complaints_registered', null, 5901::numeric, 'complaints', 'p26-t43'),
      ('K/E', 2017, null::int, 'complaints_registered', null, 6725::numeric, 'complaints', 'p26-t43'),
      ('K/E', 2018, null::int, 'complaints_registered', null, 8146::numeric, 'complaints', 'p26-t43'),
      ('K/E', 2019, null::int, 'complaints_registered', null, 9724::numeric, 'complaints', 'p26-t43'),
      ('K/E', 2020, null::int, 'complaints_registered', null, 6847::numeric, 'complaints', 'p26-t43'),
      ('K/E', 2021, null::int, 'complaints_registered', null, 6667::numeric, 'complaints', 'p26-t43'),
      ('K/E', 2022, null::int, 'complaints_registered', null, 7529::numeric, 'complaints', 'p26-t43'),
      ('K/E', 2023, null::int, 'complaints_registered', null, 8577::numeric, 'complaints', 'p26-t43'),
      ('K/E', 2024, null::int, 'complaints_registered', null, 8145::numeric, 'complaints', 'p26-t43'),
      ('K/E', 2025, null::int, 'complaints_registered', null, 9474::numeric, 'complaints', 'p26-t43'),
      ('K/E', 2025, null::int, 'population', null, 867906::numeric, 'people', 'p26-t43'),
      ('K/W', 2016, null::int, 'complaints_registered', null, 6374::numeric, 'complaints', 'p26-t43'),
      ('K/W', 2017, null::int, 'complaints_registered', null, 8349::numeric, 'complaints', 'p26-t43'),
      ('K/W', 2018, null::int, 'complaints_registered', null, 9465::numeric, 'complaints', 'p26-t43'),
      ('K/W', 2019, null::int, 'complaints_registered', null, 10399::numeric, 'complaints', 'p26-t43'),
      ('K/W', 2020, null::int, 'complaints_registered', null, 7456::numeric, 'complaints', 'p26-t43'),
      ('K/W', 2021, null::int, 'complaints_registered', null, 6845::numeric, 'complaints', 'p26-t43'),
      ('K/W', 2022, null::int, 'complaints_registered', null, 8667::numeric, 'complaints', 'p26-t43'),
      ('K/W', 2023, null::int, 'complaints_registered', null, 9251::numeric, 'complaints', 'p26-t43'),
      ('K/W', 2024, null::int, 'complaints_registered', null, 7945::numeric, 'complaints', 'p26-t43'),
      ('K/W', 2025, null::int, 'complaints_registered', null, 7722::numeric, 'complaints', 'p26-t43'),
      ('K/W', 2025, null::int, 'population', null, 788691::numeric, 'people', 'p26-t43'),
      ('L', 2016, null::int, 'complaints_registered', null, 7498::numeric, 'complaints', 'p26-t43'),
      ('L', 2017, null::int, 'complaints_registered', null, 7282::numeric, 'complaints', 'p26-t43'),
      ('L', 2018, null::int, 'complaints_registered', null, 7242::numeric, 'complaints', 'p26-t43'),
      ('L', 2019, null::int, 'complaints_registered', null, 7560::numeric, 'complaints', 'p26-t43'),
      ('L', 2020, null::int, 'complaints_registered', null, 5862::numeric, 'complaints', 'p26-t43'),
      ('L', 2021, null::int, 'complaints_registered', null, 6310::numeric, 'complaints', 'p26-t43'),
      ('L', 2022, null::int, 'complaints_registered', null, 6575::numeric, 'complaints', 'p26-t43'),
      ('L', 2023, null::int, 'complaints_registered', null, 7965::numeric, 'complaints', 'p26-t43'),
      ('L', 2024, null::int, 'complaints_registered', null, 7047::numeric, 'complaints', 'p26-t43'),
      ('L', 2025, null::int, 'complaints_registered', null, 6956::numeric, 'complaints', 'p26-t43'),
      ('L', 2025, null::int, 'population', null, 950431::numeric, 'people', 'p26-t43'),
      ('M/E', 2016, null::int, 'complaints_registered', null, 3468::numeric, 'complaints', 'p26-t43'),
      ('M/E', 2017, null::int, 'complaints_registered', null, 3391::numeric, 'complaints', 'p26-t43'),
      ('M/E', 2018, null::int, 'complaints_registered', null, 4232::numeric, 'complaints', 'p26-t43'),
      ('M/E', 2019, null::int, 'complaints_registered', null, 4334::numeric, 'complaints', 'p26-t43'),
      ('M/E', 2020, null::int, 'complaints_registered', null, 3525::numeric, 'complaints', 'p26-t43'),
      ('M/E', 2021, null::int, 'complaints_registered', null, 3807::numeric, 'complaints', 'p26-t43'),
      ('M/E', 2022, null::int, 'complaints_registered', null, 4023::numeric, 'complaints', 'p26-t43'),
      ('M/E', 2023, null::int, 'complaints_registered', null, 4711::numeric, 'complaints', 'p26-t43'),
      ('M/E', 2024, null::int, 'complaints_registered', null, 4060::numeric, 'complaints', 'p26-t43'),
      ('M/E', 2025, null::int, 'complaints_registered', null, 4456::numeric, 'complaints', 'p26-t43'),
      ('M/E', 2025, null::int, 'population', null, 850877::numeric, 'people', 'p26-t43'),
      ('M/W', 2016, null::int, 'complaints_registered', null, 2709::numeric, 'complaints', 'p26-t43'),
      ('M/W', 2017, null::int, 'complaints_registered', null, 3123::numeric, 'complaints', 'p26-t43'),
      ('M/W', 2018, null::int, 'complaints_registered', null, 4331::numeric, 'complaints', 'p26-t43'),
      ('M/W', 2019, null::int, 'complaints_registered', null, 4387::numeric, 'complaints', 'p26-t43'),
      ('M/W', 2020, null::int, 'complaints_registered', null, 3438::numeric, 'complaints', 'p26-t43'),
      ('M/W', 2021, null::int, 'complaints_registered', null, 4086::numeric, 'complaints', 'p26-t43'),
      ('M/W', 2022, null::int, 'complaints_registered', null, 4027::numeric, 'complaints', 'p26-t43'),
      ('M/W', 2023, null::int, 'complaints_registered', null, 4026::numeric, 'complaints', 'p26-t43'),
      ('M/W', 2024, null::int, 'complaints_registered', null, 4032::numeric, 'complaints', 'p26-t43'),
      ('M/W', 2025, null::int, 'complaints_registered', null, 4019::numeric, 'complaints', 'p26-t43'),
      ('M/W', 2025, null::int, 'population', null, 433900::numeric, 'people', 'p26-t43'),
      ('N', 2016, null::int, 'complaints_registered', null, 3559::numeric, 'complaints', 'p26-t43'),
      ('N', 2017, null::int, 'complaints_registered', null, 6088::numeric, 'complaints', 'p26-t43'),
      ('N', 2018, null::int, 'complaints_registered', null, 6570::numeric, 'complaints', 'p26-t43'),
      ('N', 2019, null::int, 'complaints_registered', null, 6843::numeric, 'complaints', 'p26-t43'),
      ('N', 2020, null::int, 'complaints_registered', null, 4981::numeric, 'complaints', 'p26-t43'),
      ('N', 2021, null::int, 'complaints_registered', null, 4045::numeric, 'complaints', 'p26-t43'),
      ('N', 2022, null::int, 'complaints_registered', null, 4400::numeric, 'complaints', 'p26-t43'),
      ('N', 2023, null::int, 'complaints_registered', null, 6604::numeric, 'complaints', 'p26-t43'),
      ('N', 2024, null::int, 'complaints_registered', null, 5428::numeric, 'complaints', 'p26-t43'),
      ('N', 2025, null::int, 'complaints_registered', null, 6465::numeric, 'complaints', 'p26-t43'),
      ('N', 2025, null::int, 'population', null, 656132::numeric, 'people', 'p26-t43'),
      ('P/N', 2016, null::int, 'complaints_registered', null, 4955::numeric, 'complaints', 'p26-t43'),
      ('P/N', 2017, null::int, 'complaints_registered', null, 5374::numeric, 'complaints', 'p26-t43'),
      ('P/N', 2018, null::int, 'complaints_registered', null, 6586::numeric, 'complaints', 'p26-t43'),
      ('P/N', 2019, null::int, 'complaints_registered', null, 8019::numeric, 'complaints', 'p26-t43'),
      ('P/N', 2020, null::int, 'complaints_registered', null, 6073::numeric, 'complaints', 'p26-t43'),
      ('P/N', 2021, null::int, 'complaints_registered', null, 6177::numeric, 'complaints', 'p26-t43'),
      ('P/N', 2022, null::int, 'complaints_registered', null, 6910::numeric, 'complaints', 'p26-t43'),
      ('P/N', 2023, null::int, 'complaints_registered', null, 7830::numeric, 'complaints', 'p26-t43'),
      ('P/N', 2024, null::int, 'complaints_registered', null, 7327::numeric, 'complaints', 'p26-t43'),
      ('P/N', 2025, null::int, 'complaints_registered', null, 7784::numeric, 'complaints', 'p26-t43'),
      ('P/N', 2025, null::int, 'population', null, 991665::numeric, 'people', 'p26-t43'),
      ('P/S', 2016, null::int, 'complaints_registered', null, 3450::numeric, 'complaints', 'p26-t43'),
      ('P/S', 2017, null::int, 'complaints_registered', null, 3227::numeric, 'complaints', 'p26-t43'),
      ('P/S', 2018, null::int, 'complaints_registered', null, 4855::numeric, 'complaints', 'p26-t43'),
      ('P/S', 2019, null::int, 'complaints_registered', null, 5133::numeric, 'complaints', 'p26-t43'),
      ('P/S', 2020, null::int, 'complaints_registered', null, 3168::numeric, 'complaints', 'p26-t43'),
      ('P/S', 2021, null::int, 'complaints_registered', null, 3133::numeric, 'complaints', 'p26-t43'),
      ('P/S', 2022, null::int, 'complaints_registered', null, 3471::numeric, 'complaints', 'p26-t43'),
      ('P/S', 2023, null::int, 'complaints_registered', null, 4521::numeric, 'complaints', 'p26-t43'),
      ('P/S', 2024, null::int, 'complaints_registered', null, 5156::numeric, 'complaints', 'p26-t43'),
      ('P/S', 2025, null::int, 'complaints_registered', null, 5122::numeric, 'complaints', 'p26-t43'),
      ('P/S', 2025, null::int, 'population', null, 488273::numeric, 'people', 'p26-t43'),
      ('R/C', 2016, null::int, 'complaints_registered', null, 4092::numeric, 'complaints', 'p26-t43'),
      ('R/C', 2017, null::int, 'complaints_registered', null, 4368::numeric, 'complaints', 'p26-t43'),
      ('R/C', 2018, null::int, 'complaints_registered', null, 5315::numeric, 'complaints', 'p26-t43'),
      ('R/C', 2019, null::int, 'complaints_registered', null, 6398::numeric, 'complaints', 'p26-t43'),
      ('R/C', 2020, null::int, 'complaints_registered', null, 4506::numeric, 'complaints', 'p26-t43'),
      ('R/C', 2021, null::int, 'complaints_registered', null, 4641::numeric, 'complaints', 'p26-t43'),
      ('R/C', 2022, null::int, 'complaints_registered', null, 5178::numeric, 'complaints', 'p26-t43'),
      ('R/C', 2023, null::int, 'complaints_registered', null, 5942::numeric, 'complaints', 'p26-t43'),
      ('R/C', 2024, null::int, 'complaints_registered', null, 5372::numeric, 'complaints', 'p26-t43'),
      ('R/C', 2025, null::int, 'complaints_registered', null, 5458::numeric, 'complaints', 'p26-t43'),
      ('R/C', 2025, null::int, 'population', null, 592198::numeric, 'people', 'p26-t43'),
      ('R/N', 2016, null::int, 'complaints_registered', null, 1542::numeric, 'complaints', 'p26-t43'),
      ('R/N', 2017, null::int, 'complaints_registered', null, 1792::numeric, 'complaints', 'p26-t43'),
      ('R/N', 2018, null::int, 'complaints_registered', null, 2171::numeric, 'complaints', 'p26-t43'),
      ('R/N', 2019, null::int, 'complaints_registered', null, 2729::numeric, 'complaints', 'p26-t43'),
      ('R/N', 2020, null::int, 'complaints_registered', null, 2185::numeric, 'complaints', 'p26-t43'),
      ('R/N', 2021, null::int, 'complaints_registered', null, 2017::numeric, 'complaints', 'p26-t43'),
      ('R/N', 2022, null::int, 'complaints_registered', null, 2367::numeric, 'complaints', 'p26-t43'),
      ('R/N', 2023, null::int, 'complaints_registered', null, 2954::numeric, 'complaints', 'p26-t43'),
      ('R/N', 2024, null::int, 'complaints_registered', null, 3166::numeric, 'complaints', 'p26-t43'),
      ('R/N', 2025, null::int, 'complaints_registered', null, 3176::numeric, 'complaints', 'p26-t43'),
      ('R/N', 2025, null::int, 'population', null, 454416::numeric, 'people', 'p26-t43'),
      ('R/S', 2016, null::int, 'complaints_registered', null, 3855::numeric, 'complaints', 'p26-t43'),
      ('R/S', 2017, null::int, 'complaints_registered', null, 4079::numeric, 'complaints', 'p26-t43'),
      ('R/S', 2018, null::int, 'complaints_registered', null, 6249::numeric, 'complaints', 'p26-t43'),
      ('R/S', 2019, null::int, 'complaints_registered', null, 6008::numeric, 'complaints', 'p26-t43'),
      ('R/S', 2020, null::int, 'complaints_registered', null, 4341::numeric, 'complaints', 'p26-t43'),
      ('R/S', 2021, null::int, 'complaints_registered', null, 4064::numeric, 'complaints', 'p26-t43'),
      ('R/S', 2022, null::int, 'complaints_registered', null, 4712::numeric, 'complaints', 'p26-t43'),
      ('R/S', 2023, null::int, 'complaints_registered', null, 5445::numeric, 'complaints', 'p26-t43'),
      ('R/S', 2024, null::int, 'complaints_registered', null, 4840::numeric, 'complaints', 'p26-t43'),
      ('R/S', 2025, null::int, 'complaints_registered', null, 5121::numeric, 'complaints', 'p26-t43'),
      ('R/S', 2025, null::int, 'population', null, 728162::numeric, 'people', 'p26-t43'),
      ('S', 2016, null::int, 'complaints_registered', null, 3040::numeric, 'complaints', 'p26-t43'),
      ('S', 2017, null::int, 'complaints_registered', null, 3923::numeric, 'complaints', 'p26-t43'),
      ('S', 2018, null::int, 'complaints_registered', null, 5115::numeric, 'complaints', 'p26-t43'),
      ('S', 2019, null::int, 'complaints_registered', null, 6144::numeric, 'complaints', 'p26-t43'),
      ('S', 2020, null::int, 'complaints_registered', null, 4480::numeric, 'complaints', 'p26-t43'),
      ('S', 2021, null::int, 'complaints_registered', null, 3820::numeric, 'complaints', 'p26-t43'),
      ('S', 2022, null::int, 'complaints_registered', null, 5351::numeric, 'complaints', 'p26-t43'),
      ('S', 2023, null::int, 'complaints_registered', null, 6649::numeric, 'complaints', 'p26-t43'),
      ('S', 2024, null::int, 'complaints_registered', null, 6221::numeric, 'complaints', 'p26-t43'),
      ('S', 2025, null::int, 'complaints_registered', null, 13116::numeric, 'complaints', 'p26-t43'),
      ('S', 2025, null::int, 'population', null, 783524::numeric, 'people', 'p26-t43'),
      ('T', 2016, null::int, 'complaints_registered', null, 1593::numeric, 'complaints', 'p26-t43'),
      ('T', 2017, null::int, 'complaints_registered', null, 2050::numeric, 'complaints', 'p26-t43'),
      ('T', 2018, null::int, 'complaints_registered', null, 2611::numeric, 'complaints', 'p26-t43'),
      ('T', 2019, null::int, 'complaints_registered', null, 2737::numeric, 'complaints', 'p26-t43'),
      ('T', 2020, null::int, 'complaints_registered', null, 2054::numeric, 'complaints', 'p26-t43'),
      ('T', 2021, null::int, 'complaints_registered', null, 1751::numeric, 'complaints', 'p26-t43'),
      ('T', 2022, null::int, 'complaints_registered', null, 2214::numeric, 'complaints', 'p26-t43'),
      ('T', 2023, null::int, 'complaints_registered', null, 2817::numeric, 'complaints', 'p26-t43'),
      ('T', 2024, null::int, 'complaints_registered', null, 3055::numeric, 'complaints', 'p26-t43'),
      ('T', 2025, null::int, 'complaints_registered', null, 3021::numeric, 'complaints', 'p26-t43'),
      ('T', 2025, null::int, 'population', null, 359708::numeric, 'people', 'p26-t43'),
      (null, 2025, null::int, 'complaints_unassigned_ward', null, 7641::numeric, 'complaints', 'p26-t43'),
      ('A', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 256::numeric, 'complaints', 'p26-t39'),
      ('A', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 228::numeric, 'complaints', 'p26-t39'),
      ('A', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 265::numeric, 'complaints', 'p26-t39'),
      ('A', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 361::numeric, 'complaints', 'p26-t39'),
      ('A', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 258::numeric, 'complaints', 'p26-t39'),
      ('A', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 216::numeric, 'complaints', 'p26-t39'),
      ('A', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 294::numeric, 'complaints', 'p26-t39'),
      ('A', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 376::numeric, 'complaints', 'p26-t39'),
      ('A', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 296::numeric, 'complaints', 'p26-t39'),
      ('A', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 364::numeric, 'complaints', 'p26-t39'),
      ('B', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 182::numeric, 'complaints', 'p26-t39'),
      ('B', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 205::numeric, 'complaints', 'p26-t39'),
      ('B', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 312::numeric, 'complaints', 'p26-t39'),
      ('B', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 391::numeric, 'complaints', 'p26-t39'),
      ('B', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 332::numeric, 'complaints', 'p26-t39'),
      ('B', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 314::numeric, 'complaints', 'p26-t39'),
      ('B', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 336::numeric, 'complaints', 'p26-t39'),
      ('B', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 583::numeric, 'complaints', 'p26-t39'),
      ('B', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 599::numeric, 'complaints', 'p26-t39'),
      ('B', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 553::numeric, 'complaints', 'p26-t39'),
      ('C', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 270::numeric, 'complaints', 'p26-t39'),
      ('C', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 498::numeric, 'complaints', 'p26-t39'),
      ('C', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 730::numeric, 'complaints', 'p26-t39'),
      ('C', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 687::numeric, 'complaints', 'p26-t39'),
      ('C', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 602::numeric, 'complaints', 'p26-t39'),
      ('C', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 461::numeric, 'complaints', 'p26-t39'),
      ('C', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 473::numeric, 'complaints', 'p26-t39'),
      ('C', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1022::numeric, 'complaints', 'p26-t39'),
      ('C', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1560::numeric, 'complaints', 'p26-t39'),
      ('C', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1208::numeric, 'complaints', 'p26-t39'),
      ('D', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 478::numeric, 'complaints', 'p26-t39'),
      ('D', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 524::numeric, 'complaints', 'p26-t39'),
      ('D', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 675::numeric, 'complaints', 'p26-t39'),
      ('D', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 605::numeric, 'complaints', 'p26-t39'),
      ('D', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 548::numeric, 'complaints', 'p26-t39'),
      ('D', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 404::numeric, 'complaints', 'p26-t39'),
      ('D', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 464::numeric, 'complaints', 'p26-t39'),
      ('D', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 752::numeric, 'complaints', 'p26-t39'),
      ('D', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 795::numeric, 'complaints', 'p26-t39'),
      ('D', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 803::numeric, 'complaints', 'p26-t39'),
      ('E', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 551::numeric, 'complaints', 'p26-t39'),
      ('E', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 474::numeric, 'complaints', 'p26-t39'),
      ('E', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 830::numeric, 'complaints', 'p26-t39'),
      ('E', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 840::numeric, 'complaints', 'p26-t39'),
      ('E', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 560::numeric, 'complaints', 'p26-t39'),
      ('E', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 479::numeric, 'complaints', 'p26-t39'),
      ('E', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 602::numeric, 'complaints', 'p26-t39'),
      ('E', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1155::numeric, 'complaints', 'p26-t39'),
      ('E', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1323::numeric, 'complaints', 'p26-t39'),
      ('E', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1559::numeric, 'complaints', 'p26-t39'),
      ('F/N', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 212::numeric, 'complaints', 'p26-t39'),
      ('F/N', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 397::numeric, 'complaints', 'p26-t39'),
      ('F/N', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 531::numeric, 'complaints', 'p26-t39'),
      ('F/N', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 871::numeric, 'complaints', 'p26-t39'),
      ('F/N', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 755::numeric, 'complaints', 'p26-t39'),
      ('F/N', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 562::numeric, 'complaints', 'p26-t39'),
      ('F/N', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 704::numeric, 'complaints', 'p26-t39'),
      ('F/N', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1441::numeric, 'complaints', 'p26-t39'),
      ('F/N', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1124::numeric, 'complaints', 'p26-t39'),
      ('F/N', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1198::numeric, 'complaints', 'p26-t39'),
      ('F/S', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 139::numeric, 'complaints', 'p26-t39'),
      ('F/S', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 213::numeric, 'complaints', 'p26-t39'),
      ('F/S', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 268::numeric, 'complaints', 'p26-t39'),
      ('F/S', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 409::numeric, 'complaints', 'p26-t39'),
      ('F/S', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 349::numeric, 'complaints', 'p26-t39'),
      ('F/S', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 249::numeric, 'complaints', 'p26-t39'),
      ('F/S', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 314::numeric, 'complaints', 'p26-t39'),
      ('F/S', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 522::numeric, 'complaints', 'p26-t39'),
      ('F/S', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 559::numeric, 'complaints', 'p26-t39'),
      ('F/S', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 526::numeric, 'complaints', 'p26-t39'),
      ('G/N', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 310::numeric, 'complaints', 'p26-t39'),
      ('G/N', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 506::numeric, 'complaints', 'p26-t39'),
      ('G/N', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 542::numeric, 'complaints', 'p26-t39'),
      ('G/N', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 661::numeric, 'complaints', 'p26-t39'),
      ('G/N', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 389::numeric, 'complaints', 'p26-t39'),
      ('G/N', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 364::numeric, 'complaints', 'p26-t39'),
      ('G/N', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 425::numeric, 'complaints', 'p26-t39'),
      ('G/N', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1098::numeric, 'complaints', 'p26-t39'),
      ('G/N', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1181::numeric, 'complaints', 'p26-t39'),
      ('G/N', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1315::numeric, 'complaints', 'p26-t39'),
      ('G/S', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 186::numeric, 'complaints', 'p26-t39'),
      ('G/S', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 320::numeric, 'complaints', 'p26-t39'),
      ('G/S', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 399::numeric, 'complaints', 'p26-t39'),
      ('G/S', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 401::numeric, 'complaints', 'p26-t39'),
      ('G/S', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 291::numeric, 'complaints', 'p26-t39'),
      ('G/S', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 268::numeric, 'complaints', 'p26-t39'),
      ('G/S', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 412::numeric, 'complaints', 'p26-t39'),
      ('G/S', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 522::numeric, 'complaints', 'p26-t39'),
      ('G/S', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 774::numeric, 'complaints', 'p26-t39'),
      ('G/S', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 536::numeric, 'complaints', 'p26-t39'),
      ('H/E', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 228::numeric, 'complaints', 'p26-t39'),
      ('H/E', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 307::numeric, 'complaints', 'p26-t39'),
      ('H/E', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 429::numeric, 'complaints', 'p26-t39'),
      ('H/E', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 540::numeric, 'complaints', 'p26-t39'),
      ('H/E', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 364::numeric, 'complaints', 'p26-t39'),
      ('H/E', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 321::numeric, 'complaints', 'p26-t39'),
      ('H/E', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 386::numeric, 'complaints', 'p26-t39'),
      ('H/E', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 836::numeric, 'complaints', 'p26-t39'),
      ('H/E', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 892::numeric, 'complaints', 'p26-t39'),
      ('H/E', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 742::numeric, 'complaints', 'p26-t39'),
      ('H/W', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 381::numeric, 'complaints', 'p26-t39'),
      ('H/W', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 501::numeric, 'complaints', 'p26-t39'),
      ('H/W', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 661::numeric, 'complaints', 'p26-t39'),
      ('H/W', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 659::numeric, 'complaints', 'p26-t39'),
      ('H/W', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 380::numeric, 'complaints', 'p26-t39'),
      ('H/W', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 467::numeric, 'complaints', 'p26-t39'),
      ('H/W', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 464::numeric, 'complaints', 'p26-t39'),
      ('H/W', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1086::numeric, 'complaints', 'p26-t39'),
      ('H/W', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 948::numeric, 'complaints', 'p26-t39'),
      ('H/W', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 897::numeric, 'complaints', 'p26-t39'),
      ('K/E', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 409::numeric, 'complaints', 'p26-t39'),
      ('K/E', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 588::numeric, 'complaints', 'p26-t39'),
      ('K/E', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 934::numeric, 'complaints', 'p26-t39'),
      ('K/E', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1019::numeric, 'complaints', 'p26-t39'),
      ('K/E', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 774::numeric, 'complaints', 'p26-t39'),
      ('K/E', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 718::numeric, 'complaints', 'p26-t39'),
      ('K/E', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 774::numeric, 'complaints', 'p26-t39'),
      ('K/E', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1419::numeric, 'complaints', 'p26-t39'),
      ('K/E', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1489::numeric, 'complaints', 'p26-t39'),
      ('K/E', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1204::numeric, 'complaints', 'p26-t39'),
      ('K/W', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 441::numeric, 'complaints', 'p26-t39'),
      ('K/W', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 691::numeric, 'complaints', 'p26-t39'),
      ('K/W', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 960::numeric, 'complaints', 'p26-t39'),
      ('K/W', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1680::numeric, 'complaints', 'p26-t39'),
      ('K/W', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 983::numeric, 'complaints', 'p26-t39'),
      ('K/W', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 918::numeric, 'complaints', 'p26-t39'),
      ('K/W', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1105::numeric, 'complaints', 'p26-t39'),
      ('K/W', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 2112::numeric, 'complaints', 'p26-t39'),
      ('K/W', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 2056::numeric, 'complaints', 'p26-t39'),
      ('K/W', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 2207::numeric, 'complaints', 'p26-t39'),
      ('L', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 454::numeric, 'complaints', 'p26-t39'),
      ('L', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 513::numeric, 'complaints', 'p26-t39'),
      ('L', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 596::numeric, 'complaints', 'p26-t39'),
      ('L', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 827::numeric, 'complaints', 'p26-t39'),
      ('L', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 459::numeric, 'complaints', 'p26-t39'),
      ('L', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 608::numeric, 'complaints', 'p26-t39'),
      ('L', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 557::numeric, 'complaints', 'p26-t39'),
      ('L', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1677::numeric, 'complaints', 'p26-t39'),
      ('L', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1214::numeric, 'complaints', 'p26-t39'),
      ('L', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1543::numeric, 'complaints', 'p26-t39'),
      ('M/E', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 217::numeric, 'complaints', 'p26-t39'),
      ('M/E', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 332::numeric, 'complaints', 'p26-t39'),
      ('M/E', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 463::numeric, 'complaints', 'p26-t39'),
      ('M/E', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 597::numeric, 'complaints', 'p26-t39'),
      ('M/E', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 367::numeric, 'complaints', 'p26-t39'),
      ('M/E', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 616::numeric, 'complaints', 'p26-t39'),
      ('M/E', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 543::numeric, 'complaints', 'p26-t39'),
      ('M/E', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1007::numeric, 'complaints', 'p26-t39'),
      ('M/E', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 703::numeric, 'complaints', 'p26-t39'),
      ('M/E', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 899::numeric, 'complaints', 'p26-t39'),
      ('M/W', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 288::numeric, 'complaints', 'p26-t39'),
      ('M/W', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 306::numeric, 'complaints', 'p26-t39'),
      ('M/W', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 459::numeric, 'complaints', 'p26-t39'),
      ('M/W', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 507::numeric, 'complaints', 'p26-t39'),
      ('M/W', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 438::numeric, 'complaints', 'p26-t39'),
      ('M/W', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 458::numeric, 'complaints', 'p26-t39'),
      ('M/W', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 411::numeric, 'complaints', 'p26-t39'),
      ('M/W', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 795::numeric, 'complaints', 'p26-t39'),
      ('M/W', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 773::numeric, 'complaints', 'p26-t39'),
      ('M/W', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 779::numeric, 'complaints', 'p26-t39'),
      ('N', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 350::numeric, 'complaints', 'p26-t39'),
      ('N', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 551::numeric, 'complaints', 'p26-t39'),
      ('N', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 890::numeric, 'complaints', 'p26-t39'),
      ('N', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 801::numeric, 'complaints', 'p26-t39'),
      ('N', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 520::numeric, 'complaints', 'p26-t39'),
      ('N', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 468::numeric, 'complaints', 'p26-t39'),
      ('N', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 517::numeric, 'complaints', 'p26-t39'),
      ('N', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1064::numeric, 'complaints', 'p26-t39'),
      ('N', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 927::numeric, 'complaints', 'p26-t39'),
      ('N', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 836::numeric, 'complaints', 'p26-t39'),
      ('P/N', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 328::numeric, 'complaints', 'p26-t39'),
      ('P/N', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 557::numeric, 'complaints', 'p26-t39'),
      ('P/N', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 880::numeric, 'complaints', 'p26-t39'),
      ('P/N', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1106::numeric, 'complaints', 'p26-t39'),
      ('P/N', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 622::numeric, 'complaints', 'p26-t39'),
      ('P/N', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 636::numeric, 'complaints', 'p26-t39'),
      ('P/N', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 773::numeric, 'complaints', 'p26-t39'),
      ('P/N', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1533::numeric, 'complaints', 'p26-t39'),
      ('P/N', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1376::numeric, 'complaints', 'p26-t39'),
      ('P/N', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1495::numeric, 'complaints', 'p26-t39'),
      ('P/S', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 327::numeric, 'complaints', 'p26-t39'),
      ('P/S', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 439::numeric, 'complaints', 'p26-t39'),
      ('P/S', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 845::numeric, 'complaints', 'p26-t39'),
      ('P/S', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 842::numeric, 'complaints', 'p26-t39'),
      ('P/S', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 428::numeric, 'complaints', 'p26-t39'),
      ('P/S', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 498::numeric, 'complaints', 'p26-t39'),
      ('P/S', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 450::numeric, 'complaints', 'p26-t39'),
      ('P/S', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1366::numeric, 'complaints', 'p26-t39'),
      ('P/S', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1944::numeric, 'complaints', 'p26-t39'),
      ('P/S', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1623::numeric, 'complaints', 'p26-t39'),
      ('R/C', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 477::numeric, 'complaints', 'p26-t39'),
      ('R/C', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 672::numeric, 'complaints', 'p26-t39'),
      ('R/C', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 788::numeric, 'complaints', 'p26-t39'),
      ('R/C', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 997::numeric, 'complaints', 'p26-t39'),
      ('R/C', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 640::numeric, 'complaints', 'p26-t39'),
      ('R/C', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 712::numeric, 'complaints', 'p26-t39'),
      ('R/C', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 623::numeric, 'complaints', 'p26-t39'),
      ('R/C', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1096::numeric, 'complaints', 'p26-t39'),
      ('R/C', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 879::numeric, 'complaints', 'p26-t39'),
      ('R/C', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 969::numeric, 'complaints', 'p26-t39'),
      ('R/N', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 96::numeric, 'complaints', 'p26-t39'),
      ('R/N', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 142::numeric, 'complaints', 'p26-t39'),
      ('R/N', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 247::numeric, 'complaints', 'p26-t39'),
      ('R/N', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 345::numeric, 'complaints', 'p26-t39'),
      ('R/N', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 294::numeric, 'complaints', 'p26-t39'),
      ('R/N', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 290::numeric, 'complaints', 'p26-t39'),
      ('R/N', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 338::numeric, 'complaints', 'p26-t39'),
      ('R/N', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 599::numeric, 'complaints', 'p26-t39'),
      ('R/N', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 624::numeric, 'complaints', 'p26-t39'),
      ('R/N', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 699::numeric, 'complaints', 'p26-t39'),
      ('R/S', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 336::numeric, 'complaints', 'p26-t39'),
      ('R/S', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 478::numeric, 'complaints', 'p26-t39'),
      ('R/S', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 721::numeric, 'complaints', 'p26-t39'),
      ('R/S', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 922::numeric, 'complaints', 'p26-t39'),
      ('R/S', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 546::numeric, 'complaints', 'p26-t39'),
      ('R/S', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 460::numeric, 'complaints', 'p26-t39'),
      ('R/S', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 460::numeric, 'complaints', 'p26-t39'),
      ('R/S', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 967::numeric, 'complaints', 'p26-t39'),
      ('R/S', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 956::numeric, 'complaints', 'p26-t39'),
      ('R/S', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1110::numeric, 'complaints', 'p26-t39'),
      ('S', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 284::numeric, 'complaints', 'p26-t39'),
      ('S', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 482::numeric, 'complaints', 'p26-t39'),
      ('S', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 762::numeric, 'complaints', 'p26-t39'),
      ('S', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 737::numeric, 'complaints', 'p26-t39'),
      ('S', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 474::numeric, 'complaints', 'p26-t39'),
      ('S', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 390::numeric, 'complaints', 'p26-t39'),
      ('S', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 702::numeric, 'complaints', 'p26-t39'),
      ('S', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1367::numeric, 'complaints', 'p26-t39'),
      ('S', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 1685::numeric, 'complaints', 'p26-t39'),
      ('S', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 3036::numeric, 'complaints', 'p26-t39'),
      ('T', 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 130::numeric, 'complaints', 'p26-t39'),
      ('T', 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 220::numeric, 'complaints', 'p26-t39'),
      ('T', 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 307::numeric, 'complaints', 'p26-t39'),
      ('T', 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 311::numeric, 'complaints', 'p26-t39'),
      ('T', 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 222::numeric, 'complaints', 'p26-t39'),
      ('T', 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 179::numeric, 'complaints', 'p26-t39'),
      ('T', 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 224::numeric, 'complaints', 'p26-t39'),
      ('T', 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 295::numeric, 'complaints', 'p26-t39'),
      ('T', 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 354::numeric, 'complaints', 'p26-t39'),
      ('T', 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 405::numeric, 'complaints', 'p26-t39'),
      (null, 2025, null::int, 'complaints_unassigned_ward', 'Solid Waste Management (SWM)', 1432::numeric, 'complaints', 'p26-t39'),
      ('A', 2016, null::int, 'complaints_registered', 'Drainage', 320::numeric, 'complaints', 'p26-t41'),
      ('A', 2017, null::int, 'complaints_registered', 'Drainage', 373::numeric, 'complaints', 'p26-t41'),
      ('A', 2018, null::int, 'complaints_registered', 'Drainage', 469::numeric, 'complaints', 'p26-t41'),
      ('A', 2019, null::int, 'complaints_registered', 'Drainage', 622::numeric, 'complaints', 'p26-t41'),
      ('A', 2020, null::int, 'complaints_registered', 'Drainage', 344::numeric, 'complaints', 'p26-t41'),
      ('A', 2021, null::int, 'complaints_registered', 'Drainage', 387::numeric, 'complaints', 'p26-t41'),
      ('A', 2022, null::int, 'complaints_registered', 'Drainage', 474::numeric, 'complaints', 'p26-t41'),
      ('A', 2023, null::int, 'complaints_registered', 'Drainage', 377::numeric, 'complaints', 'p26-t41'),
      ('A', 2024, null::int, 'complaints_registered', 'Drainage', 356::numeric, 'complaints', 'p26-t41'),
      ('A', 2025, null::int, 'complaints_registered', 'Drainage', 256::numeric, 'complaints', 'p26-t41'),
      ('B', 2016, null::int, 'complaints_registered', 'Drainage', 315::numeric, 'complaints', 'p26-t41'),
      ('B', 2017, null::int, 'complaints_registered', 'Drainage', 379::numeric, 'complaints', 'p26-t41'),
      ('B', 2018, null::int, 'complaints_registered', 'Drainage', 710::numeric, 'complaints', 'p26-t41'),
      ('B', 2019, null::int, 'complaints_registered', 'Drainage', 751::numeric, 'complaints', 'p26-t41'),
      ('B', 2020, null::int, 'complaints_registered', 'Drainage', 420::numeric, 'complaints', 'p26-t41'),
      ('B', 2021, null::int, 'complaints_registered', 'Drainage', 523::numeric, 'complaints', 'p26-t41'),
      ('B', 2022, null::int, 'complaints_registered', 'Drainage', 754::numeric, 'complaints', 'p26-t41'),
      ('B', 2023, null::int, 'complaints_registered', 'Drainage', 621::numeric, 'complaints', 'p26-t41'),
      ('B', 2024, null::int, 'complaints_registered', 'Drainage', 453::numeric, 'complaints', 'p26-t41'),
      ('B', 2025, null::int, 'complaints_registered', 'Drainage', 395::numeric, 'complaints', 'p26-t41'),
      ('C', 2016, null::int, 'complaints_registered', 'Drainage', 287::numeric, 'complaints', 'p26-t41'),
      ('C', 2017, null::int, 'complaints_registered', 'Drainage', 521::numeric, 'complaints', 'p26-t41'),
      ('C', 2018, null::int, 'complaints_registered', 'Drainage', 552::numeric, 'complaints', 'p26-t41'),
      ('C', 2019, null::int, 'complaints_registered', 'Drainage', 630::numeric, 'complaints', 'p26-t41'),
      ('C', 2020, null::int, 'complaints_registered', 'Drainage', 482::numeric, 'complaints', 'p26-t41'),
      ('C', 2021, null::int, 'complaints_registered', 'Drainage', 473::numeric, 'complaints', 'p26-t41'),
      ('C', 2022, null::int, 'complaints_registered', 'Drainage', 552::numeric, 'complaints', 'p26-t41'),
      ('C', 2023, null::int, 'complaints_registered', 'Drainage', 583::numeric, 'complaints', 'p26-t41'),
      ('C', 2024, null::int, 'complaints_registered', 'Drainage', 568::numeric, 'complaints', 'p26-t41'),
      ('C', 2025, null::int, 'complaints_registered', 'Drainage', 547::numeric, 'complaints', 'p26-t41'),
      ('D', 2016, null::int, 'complaints_registered', 'Drainage', 995::numeric, 'complaints', 'p26-t41'),
      ('D', 2017, null::int, 'complaints_registered', 'Drainage', 989::numeric, 'complaints', 'p26-t41'),
      ('D', 2018, null::int, 'complaints_registered', 'Drainage', 1296::numeric, 'complaints', 'p26-t41'),
      ('D', 2019, null::int, 'complaints_registered', 'Drainage', 1514::numeric, 'complaints', 'p26-t41'),
      ('D', 2020, null::int, 'complaints_registered', 'Drainage', 816::numeric, 'complaints', 'p26-t41'),
      ('D', 2021, null::int, 'complaints_registered', 'Drainage', 642::numeric, 'complaints', 'p26-t41'),
      ('D', 2022, null::int, 'complaints_registered', 'Drainage', 904::numeric, 'complaints', 'p26-t41'),
      ('D', 2023, null::int, 'complaints_registered', 'Drainage', 844::numeric, 'complaints', 'p26-t41'),
      ('D', 2024, null::int, 'complaints_registered', 'Drainage', 807::numeric, 'complaints', 'p26-t41'),
      ('D', 2025, null::int, 'complaints_registered', 'Drainage', 701::numeric, 'complaints', 'p26-t41'),
      ('E', 2016, null::int, 'complaints_registered', 'Drainage', 295::numeric, 'complaints', 'p26-t41'),
      ('E', 2017, null::int, 'complaints_registered', 'Drainage', 439::numeric, 'complaints', 'p26-t41'),
      ('E', 2018, null::int, 'complaints_registered', 'Drainage', 465::numeric, 'complaints', 'p26-t41'),
      ('E', 2019, null::int, 'complaints_registered', 'Drainage', 595::numeric, 'complaints', 'p26-t41'),
      ('E', 2020, null::int, 'complaints_registered', 'Drainage', 530::numeric, 'complaints', 'p26-t41'),
      ('E', 2021, null::int, 'complaints_registered', 'Drainage', 372::numeric, 'complaints', 'p26-t41'),
      ('E', 2022, null::int, 'complaints_registered', 'Drainage', 552::numeric, 'complaints', 'p26-t41'),
      ('E', 2023, null::int, 'complaints_registered', 'Drainage', 382::numeric, 'complaints', 'p26-t41'),
      ('E', 2024, null::int, 'complaints_registered', 'Drainage', 58::numeric, 'complaints', 'p26-t41'),
      ('E', 2025, null::int, 'complaints_registered', 'Drainage', 43::numeric, 'complaints', 'p26-t41'),
      ('F/N', 2016, null::int, 'complaints_registered', 'Drainage', 245::numeric, 'complaints', 'p26-t41'),
      ('F/N', 2017, null::int, 'complaints_registered', 'Drainage', 278::numeric, 'complaints', 'p26-t41'),
      ('F/N', 2018, null::int, 'complaints_registered', 'Drainage', 530::numeric, 'complaints', 'p26-t41'),
      ('F/N', 2019, null::int, 'complaints_registered', 'Drainage', 674::numeric, 'complaints', 'p26-t41'),
      ('F/N', 2020, null::int, 'complaints_registered', 'Drainage', 336::numeric, 'complaints', 'p26-t41'),
      ('F/N', 2021, null::int, 'complaints_registered', 'Drainage', 305::numeric, 'complaints', 'p26-t41'),
      ('F/N', 2022, null::int, 'complaints_registered', 'Drainage', 420::numeric, 'complaints', 'p26-t41'),
      ('F/N', 2023, null::int, 'complaints_registered', 'Drainage', 547::numeric, 'complaints', 'p26-t41'),
      ('F/N', 2024, null::int, 'complaints_registered', 'Drainage', 526::numeric, 'complaints', 'p26-t41'),
      ('F/N', 2025, null::int, 'complaints_registered', 'Drainage', 460::numeric, 'complaints', 'p26-t41'),
      ('F/S', 2016, null::int, 'complaints_registered', 'Drainage', 191::numeric, 'complaints', 'p26-t41'),
      ('F/S', 2017, null::int, 'complaints_registered', 'Drainage', 235::numeric, 'complaints', 'p26-t41'),
      ('F/S', 2018, null::int, 'complaints_registered', 'Drainage', 360::numeric, 'complaints', 'p26-t41'),
      ('F/S', 2019, null::int, 'complaints_registered', 'Drainage', 645::numeric, 'complaints', 'p26-t41'),
      ('F/S', 2020, null::int, 'complaints_registered', 'Drainage', 382::numeric, 'complaints', 'p26-t41'),
      ('F/S', 2021, null::int, 'complaints_registered', 'Drainage', 389::numeric, 'complaints', 'p26-t41'),
      ('F/S', 2022, null::int, 'complaints_registered', 'Drainage', 724::numeric, 'complaints', 'p26-t41'),
      ('F/S', 2023, null::int, 'complaints_registered', 'Drainage', 481::numeric, 'complaints', 'p26-t41'),
      ('F/S', 2024, null::int, 'complaints_registered', 'Drainage', 377::numeric, 'complaints', 'p26-t41'),
      ('F/S', 2025, null::int, 'complaints_registered', 'Drainage', 376::numeric, 'complaints', 'p26-t41'),
      ('G/N', 2016, null::int, 'complaints_registered', 'Drainage', 471::numeric, 'complaints', 'p26-t41'),
      ('G/N', 2017, null::int, 'complaints_registered', 'Drainage', 640::numeric, 'complaints', 'p26-t41'),
      ('G/N', 2018, null::int, 'complaints_registered', 'Drainage', 834::numeric, 'complaints', 'p26-t41'),
      ('G/N', 2019, null::int, 'complaints_registered', 'Drainage', 969::numeric, 'complaints', 'p26-t41'),
      ('G/N', 2020, null::int, 'complaints_registered', 'Drainage', 564::numeric, 'complaints', 'p26-t41'),
      ('G/N', 2021, null::int, 'complaints_registered', 'Drainage', 518::numeric, 'complaints', 'p26-t41'),
      ('G/N', 2022, null::int, 'complaints_registered', 'Drainage', 658::numeric, 'complaints', 'p26-t41'),
      ('G/N', 2023, null::int, 'complaints_registered', 'Drainage', 796::numeric, 'complaints', 'p26-t41'),
      ('G/N', 2024, null::int, 'complaints_registered', 'Drainage', 718::numeric, 'complaints', 'p26-t41'),
      ('G/N', 2025, null::int, 'complaints_registered', 'Drainage', 798::numeric, 'complaints', 'p26-t41'),
      ('G/S', 2016, null::int, 'complaints_registered', 'Drainage', 252::numeric, 'complaints', 'p26-t41'),
      ('G/S', 2017, null::int, 'complaints_registered', 'Drainage', 319::numeric, 'complaints', 'p26-t41'),
      ('G/S', 2018, null::int, 'complaints_registered', 'Drainage', 547::numeric, 'complaints', 'p26-t41'),
      ('G/S', 2019, null::int, 'complaints_registered', 'Drainage', 608::numeric, 'complaints', 'p26-t41'),
      ('G/S', 2020, null::int, 'complaints_registered', 'Drainage', 361::numeric, 'complaints', 'p26-t41'),
      ('G/S', 2021, null::int, 'complaints_registered', 'Drainage', 304::numeric, 'complaints', 'p26-t41'),
      ('G/S', 2022, null::int, 'complaints_registered', 'Drainage', 401::numeric, 'complaints', 'p26-t41'),
      ('G/S', 2023, null::int, 'complaints_registered', 'Drainage', 483::numeric, 'complaints', 'p26-t41'),
      ('G/S', 2024, null::int, 'complaints_registered', 'Drainage', 620::numeric, 'complaints', 'p26-t41'),
      ('G/S', 2025, null::int, 'complaints_registered', 'Drainage', 550::numeric, 'complaints', 'p26-t41'),
      ('H/E', 2016, null::int, 'complaints_registered', 'Drainage', 603::numeric, 'complaints', 'p26-t41'),
      ('H/E', 2017, null::int, 'complaints_registered', 'Drainage', 662::numeric, 'complaints', 'p26-t41'),
      ('H/E', 2018, null::int, 'complaints_registered', 'Drainage', 856::numeric, 'complaints', 'p26-t41'),
      ('H/E', 2019, null::int, 'complaints_registered', 'Drainage', 985::numeric, 'complaints', 'p26-t41'),
      ('H/E', 2020, null::int, 'complaints_registered', 'Drainage', 742::numeric, 'complaints', 'p26-t41'),
      ('H/E', 2021, null::int, 'complaints_registered', 'Drainage', 540::numeric, 'complaints', 'p26-t41'),
      ('H/E', 2022, null::int, 'complaints_registered', 'Drainage', 773::numeric, 'complaints', 'p26-t41'),
      ('H/E', 2023, null::int, 'complaints_registered', 'Drainage', 817::numeric, 'complaints', 'p26-t41'),
      ('H/E', 2024, null::int, 'complaints_registered', 'Drainage', 779::numeric, 'complaints', 'p26-t41'),
      ('H/E', 2025, null::int, 'complaints_registered', 'Drainage', 688::numeric, 'complaints', 'p26-t41'),
      ('H/W', 2016, null::int, 'complaints_registered', 'Drainage', 664::numeric, 'complaints', 'p26-t41'),
      ('H/W', 2017, null::int, 'complaints_registered', 'Drainage', 736::numeric, 'complaints', 'p26-t41'),
      ('H/W', 2018, null::int, 'complaints_registered', 'Drainage', 1027::numeric, 'complaints', 'p26-t41'),
      ('H/W', 2019, null::int, 'complaints_registered', 'Drainage', 1102::numeric, 'complaints', 'p26-t41'),
      ('H/W', 2020, null::int, 'complaints_registered', 'Drainage', 752::numeric, 'complaints', 'p26-t41'),
      ('H/W', 2021, null::int, 'complaints_registered', 'Drainage', 622::numeric, 'complaints', 'p26-t41'),
      ('H/W', 2022, null::int, 'complaints_registered', 'Drainage', 840::numeric, 'complaints', 'p26-t41'),
      ('H/W', 2023, null::int, 'complaints_registered', 'Drainage', 979::numeric, 'complaints', 'p26-t41'),
      ('H/W', 2024, null::int, 'complaints_registered', 'Drainage', 676::numeric, 'complaints', 'p26-t41'),
      ('H/W', 2025, null::int, 'complaints_registered', 'Drainage', 642::numeric, 'complaints', 'p26-t41'),
      ('K/E', 2016, null::int, 'complaints_registered', 'Drainage', 903::numeric, 'complaints', 'p26-t41'),
      ('K/E', 2017, null::int, 'complaints_registered', 'Drainage', 1057::numeric, 'complaints', 'p26-t41'),
      ('K/E', 2018, null::int, 'complaints_registered', 'Drainage', 1353::numeric, 'complaints', 'p26-t41'),
      ('K/E', 2019, null::int, 'complaints_registered', 'Drainage', 1730::numeric, 'complaints', 'p26-t41'),
      ('K/E', 2020, null::int, 'complaints_registered', 'Drainage', 1103::numeric, 'complaints', 'p26-t41'),
      ('K/E', 2021, null::int, 'complaints_registered', 'Drainage', 993::numeric, 'complaints', 'p26-t41'),
      ('K/E', 2022, null::int, 'complaints_registered', 'Drainage', 1338::numeric, 'complaints', 'p26-t41'),
      ('K/E', 2023, null::int, 'complaints_registered', 'Drainage', 1438::numeric, 'complaints', 'p26-t41'),
      ('K/E', 2024, null::int, 'complaints_registered', 'Drainage', 1246::numeric, 'complaints', 'p26-t41'),
      ('K/E', 2025, null::int, 'complaints_registered', 'Drainage', 968::numeric, 'complaints', 'p26-t41'),
      ('K/W', 2016, null::int, 'complaints_registered', 'Drainage', 1477::numeric, 'complaints', 'p26-t41'),
      ('K/W', 2017, null::int, 'complaints_registered', 'Drainage', 1732::numeric, 'complaints', 'p26-t41'),
      ('K/W', 2018, null::int, 'complaints_registered', 'Drainage', 2072::numeric, 'complaints', 'p26-t41'),
      ('K/W', 2019, null::int, 'complaints_registered', 'Drainage', 2357::numeric, 'complaints', 'p26-t41'),
      ('K/W', 2020, null::int, 'complaints_registered', 'Drainage', 1424::numeric, 'complaints', 'p26-t41'),
      ('K/W', 2021, null::int, 'complaints_registered', 'Drainage', 1320::numeric, 'complaints', 'p26-t41'),
      ('K/W', 2022, null::int, 'complaints_registered', 'Drainage', 1698::numeric, 'complaints', 'p26-t41'),
      ('K/W', 2023, null::int, 'complaints_registered', 'Drainage', 1931::numeric, 'complaints', 'p26-t41'),
      ('K/W', 2024, null::int, 'complaints_registered', 'Drainage', 1202::numeric, 'complaints', 'p26-t41'),
      ('K/W', 2025, null::int, 'complaints_registered', 'Drainage', 1079::numeric, 'complaints', 'p26-t41'),
      ('L', 2016, null::int, 'complaints_registered', 'Drainage', 1184::numeric, 'complaints', 'p26-t41'),
      ('L', 2017, null::int, 'complaints_registered', 'Drainage', 1457::numeric, 'complaints', 'p26-t41'),
      ('L', 2018, null::int, 'complaints_registered', 'Drainage', 1620::numeric, 'complaints', 'p26-t41'),
      ('L', 2019, null::int, 'complaints_registered', 'Drainage', 1649::numeric, 'complaints', 'p26-t41'),
      ('L', 2020, null::int, 'complaints_registered', 'Drainage', 953::numeric, 'complaints', 'p26-t41'),
      ('L', 2021, null::int, 'complaints_registered', 'Drainage', 798::numeric, 'complaints', 'p26-t41'),
      ('L', 2022, null::int, 'complaints_registered', 'Drainage', 788::numeric, 'complaints', 'p26-t41'),
      ('L', 2023, null::int, 'complaints_registered', 'Drainage', 1024::numeric, 'complaints', 'p26-t41'),
      ('L', 2024, null::int, 'complaints_registered', 'Drainage', 897::numeric, 'complaints', 'p26-t41'),
      ('L', 2025, null::int, 'complaints_registered', 'Drainage', 906::numeric, 'complaints', 'p26-t41'),
      ('M/E', 2016, null::int, 'complaints_registered', 'Drainage', 325::numeric, 'complaints', 'p26-t41'),
      ('M/E', 2017, null::int, 'complaints_registered', 'Drainage', 484::numeric, 'complaints', 'p26-t41'),
      ('M/E', 2018, null::int, 'complaints_registered', 'Drainage', 691::numeric, 'complaints', 'p26-t41'),
      ('M/E', 2019, null::int, 'complaints_registered', 'Drainage', 774::numeric, 'complaints', 'p26-t41'),
      ('M/E', 2020, null::int, 'complaints_registered', 'Drainage', 552::numeric, 'complaints', 'p26-t41'),
      ('M/E', 2021, null::int, 'complaints_registered', 'Drainage', 639::numeric, 'complaints', 'p26-t41'),
      ('M/E', 2022, null::int, 'complaints_registered', 'Drainage', 576::numeric, 'complaints', 'p26-t41'),
      ('M/E', 2023, null::int, 'complaints_registered', 'Drainage', 751::numeric, 'complaints', 'p26-t41'),
      ('M/E', 2024, null::int, 'complaints_registered', 'Drainage', 814::numeric, 'complaints', 'p26-t41'),
      ('M/E', 2025, null::int, 'complaints_registered', 'Drainage', 842::numeric, 'complaints', 'p26-t41'),
      ('M/W', 2016, null::int, 'complaints_registered', 'Drainage', 514::numeric, 'complaints', 'p26-t41'),
      ('M/W', 2017, null::int, 'complaints_registered', 'Drainage', 923::numeric, 'complaints', 'p26-t41'),
      ('M/W', 2018, null::int, 'complaints_registered', 'Drainage', 1164::numeric, 'complaints', 'p26-t41'),
      ('M/W', 2019, null::int, 'complaints_registered', 'Drainage', 1103::numeric, 'complaints', 'p26-t41'),
      ('M/W', 2020, null::int, 'complaints_registered', 'Drainage', 744::numeric, 'complaints', 'p26-t41'),
      ('M/W', 2021, null::int, 'complaints_registered', 'Drainage', 673::numeric, 'complaints', 'p26-t41'),
      ('M/W', 2022, null::int, 'complaints_registered', 'Drainage', 665::numeric, 'complaints', 'p26-t41'),
      ('M/W', 2023, null::int, 'complaints_registered', 'Drainage', 653::numeric, 'complaints', 'p26-t41'),
      ('M/W', 2024, null::int, 'complaints_registered', 'Drainage', 640::numeric, 'complaints', 'p26-t41'),
      ('M/W', 2025, null::int, 'complaints_registered', 'Drainage', 623::numeric, 'complaints', 'p26-t41'),
      ('N', 2016, null::int, 'complaints_registered', 'Drainage', 376::numeric, 'complaints', 'p26-t41'),
      ('N', 2017, null::int, 'complaints_registered', 'Drainage', 999::numeric, 'complaints', 'p26-t41'),
      ('N', 2018, null::int, 'complaints_registered', 'Drainage', 1161::numeric, 'complaints', 'p26-t41'),
      ('N', 2019, null::int, 'complaints_registered', 'Drainage', 1314::numeric, 'complaints', 'p26-t41'),
      ('N', 2020, null::int, 'complaints_registered', 'Drainage', 789::numeric, 'complaints', 'p26-t41'),
      ('N', 2021, null::int, 'complaints_registered', 'Drainage', 567::numeric, 'complaints', 'p26-t41'),
      ('N', 2022, null::int, 'complaints_registered', 'Drainage', 575::numeric, 'complaints', 'p26-t41'),
      ('N', 2023, null::int, 'complaints_registered', 'Drainage', 956::numeric, 'complaints', 'p26-t41'),
      ('N', 2024, null::int, 'complaints_registered', 'Drainage', 736::numeric, 'complaints', 'p26-t41'),
      ('N', 2025, null::int, 'complaints_registered', 'Drainage', 736::numeric, 'complaints', 'p26-t41'),
      ('P/N', 2016, null::int, 'complaints_registered', 'Drainage', 585::numeric, 'complaints', 'p26-t41'),
      ('P/N', 2017, null::int, 'complaints_registered', 'Drainage', 683::numeric, 'complaints', 'p26-t41'),
      ('P/N', 2018, null::int, 'complaints_registered', 'Drainage', 871::numeric, 'complaints', 'p26-t41'),
      ('P/N', 2019, null::int, 'complaints_registered', 'Drainage', 1230::numeric, 'complaints', 'p26-t41'),
      ('P/N', 2020, null::int, 'complaints_registered', 'Drainage', 943::numeric, 'complaints', 'p26-t41'),
      ('P/N', 2021, null::int, 'complaints_registered', 'Drainage', 952::numeric, 'complaints', 'p26-t41'),
      ('P/N', 2022, null::int, 'complaints_registered', 'Drainage', 948::numeric, 'complaints', 'p26-t41'),
      ('P/N', 2023, null::int, 'complaints_registered', 'Drainage', 1114::numeric, 'complaints', 'p26-t41'),
      ('P/N', 2024, null::int, 'complaints_registered', 'Drainage', 926::numeric, 'complaints', 'p26-t41'),
      ('P/N', 2025, null::int, 'complaints_registered', 'Drainage', 1152::numeric, 'complaints', 'p26-t41'),
      ('P/S', 2016, null::int, 'complaints_registered', 'Drainage', 411::numeric, 'complaints', 'p26-t41'),
      ('P/S', 2017, null::int, 'complaints_registered', 'Drainage', 440::numeric, 'complaints', 'p26-t41'),
      ('P/S', 2018, null::int, 'complaints_registered', 'Drainage', 792::numeric, 'complaints', 'p26-t41'),
      ('P/S', 2019, null::int, 'complaints_registered', 'Drainage', 910::numeric, 'complaints', 'p26-t41'),
      ('P/S', 2020, null::int, 'complaints_registered', 'Drainage', 552::numeric, 'complaints', 'p26-t41'),
      ('P/S', 2021, null::int, 'complaints_registered', 'Drainage', 501::numeric, 'complaints', 'p26-t41'),
      ('P/S', 2022, null::int, 'complaints_registered', 'Drainage', 588::numeric, 'complaints', 'p26-t41'),
      ('P/S', 2023, null::int, 'complaints_registered', 'Drainage', 624::numeric, 'complaints', 'p26-t41'),
      ('P/S', 2024, null::int, 'complaints_registered', 'Drainage', 588::numeric, 'complaints', 'p26-t41'),
      ('P/S', 2025, null::int, 'complaints_registered', 'Drainage', 604::numeric, 'complaints', 'p26-t41'),
      ('R/C', 2016, null::int, 'complaints_registered', 'Drainage', 597::numeric, 'complaints', 'p26-t41'),
      ('R/C', 2017, null::int, 'complaints_registered', 'Drainage', 742::numeric, 'complaints', 'p26-t41'),
      ('R/C', 2018, null::int, 'complaints_registered', 'Drainage', 983::numeric, 'complaints', 'p26-t41'),
      ('R/C', 2019, null::int, 'complaints_registered', 'Drainage', 1309::numeric, 'complaints', 'p26-t41'),
      ('R/C', 2020, null::int, 'complaints_registered', 'Drainage', 788::numeric, 'complaints', 'p26-t41'),
      ('R/C', 2021, null::int, 'complaints_registered', 'Drainage', 704::numeric, 'complaints', 'p26-t41'),
      ('R/C', 2022, null::int, 'complaints_registered', 'Drainage', 673::numeric, 'complaints', 'p26-t41'),
      ('R/C', 2023, null::int, 'complaints_registered', 'Drainage', 843::numeric, 'complaints', 'p26-t41'),
      ('R/C', 2024, null::int, 'complaints_registered', 'Drainage', 554::numeric, 'complaints', 'p26-t41'),
      ('R/C', 2025, null::int, 'complaints_registered', 'Drainage', 562::numeric, 'complaints', 'p26-t41'),
      ('R/N', 2016, null::int, 'complaints_registered', 'Drainage', 203::numeric, 'complaints', 'p26-t41'),
      ('R/N', 2017, null::int, 'complaints_registered', 'Drainage', 242::numeric, 'complaints', 'p26-t41'),
      ('R/N', 2018, null::int, 'complaints_registered', 'Drainage', 330::numeric, 'complaints', 'p26-t41'),
      ('R/N', 2019, null::int, 'complaints_registered', 'Drainage', 453::numeric, 'complaints', 'p26-t41'),
      ('R/N', 2020, null::int, 'complaints_registered', 'Drainage', 333::numeric, 'complaints', 'p26-t41'),
      ('R/N', 2021, null::int, 'complaints_registered', 'Drainage', 320::numeric, 'complaints', 'p26-t41'),
      ('R/N', 2022, null::int, 'complaints_registered', 'Drainage', 386::numeric, 'complaints', 'p26-t41'),
      ('R/N', 2023, null::int, 'complaints_registered', 'Drainage', 429::numeric, 'complaints', 'p26-t41'),
      ('R/N', 2024, null::int, 'complaints_registered', 'Drainage', 356::numeric, 'complaints', 'p26-t41'),
      ('R/N', 2025, null::int, 'complaints_registered', 'Drainage', 339::numeric, 'complaints', 'p26-t41'),
      ('R/S', 2016, null::int, 'complaints_registered', 'Drainage', 540::numeric, 'complaints', 'p26-t41'),
      ('R/S', 2017, null::int, 'complaints_registered', 'Drainage', 547::numeric, 'complaints', 'p26-t41'),
      ('R/S', 2018, null::int, 'complaints_registered', 'Drainage', 627::numeric, 'complaints', 'p26-t41'),
      ('R/S', 2019, null::int, 'complaints_registered', 'Drainage', 927::numeric, 'complaints', 'p26-t41'),
      ('R/S', 2020, null::int, 'complaints_registered', 'Drainage', 692::numeric, 'complaints', 'p26-t41'),
      ('R/S', 2021, null::int, 'complaints_registered', 'Drainage', 671::numeric, 'complaints', 'p26-t41'),
      ('R/S', 2022, null::int, 'complaints_registered', 'Drainage', 849::numeric, 'complaints', 'p26-t41'),
      ('R/S', 2023, null::int, 'complaints_registered', 'Drainage', 902::numeric, 'complaints', 'p26-t41'),
      ('R/S', 2024, null::int, 'complaints_registered', 'Drainage', 612::numeric, 'complaints', 'p26-t41'),
      ('R/S', 2025, null::int, 'complaints_registered', 'Drainage', 657::numeric, 'complaints', 'p26-t41'),
      ('S', 2016, null::int, 'complaints_registered', 'Drainage', 318::numeric, 'complaints', 'p26-t41'),
      ('S', 2017, null::int, 'complaints_registered', 'Drainage', 631::numeric, 'complaints', 'p26-t41'),
      ('S', 2018, null::int, 'complaints_registered', 'Drainage', 820::numeric, 'complaints', 'p26-t41'),
      ('S', 2019, null::int, 'complaints_registered', 'Drainage', 934::numeric, 'complaints', 'p26-t41'),
      ('S', 2020, null::int, 'complaints_registered', 'Drainage', 600::numeric, 'complaints', 'p26-t41'),
      ('S', 2021, null::int, 'complaints_registered', 'Drainage', 510::numeric, 'complaints', 'p26-t41'),
      ('S', 2022, null::int, 'complaints_registered', 'Drainage', 675::numeric, 'complaints', 'p26-t41'),
      ('S', 2023, null::int, 'complaints_registered', 'Drainage', 844::numeric, 'complaints', 'p26-t41'),
      ('S', 2024, null::int, 'complaints_registered', 'Drainage', 843::numeric, 'complaints', 'p26-t41'),
      ('S', 2025, null::int, 'complaints_registered', 'Drainage', 912::numeric, 'complaints', 'p26-t41'),
      ('T', 2016, null::int, 'complaints_registered', 'Drainage', 198::numeric, 'complaints', 'p26-t41'),
      ('T', 2017, null::int, 'complaints_registered', 'Drainage', 432::numeric, 'complaints', 'p26-t41'),
      ('T', 2018, null::int, 'complaints_registered', 'Drainage', 511::numeric, 'complaints', 'p26-t41'),
      ('T', 2019, null::int, 'complaints_registered', 'Drainage', 482::numeric, 'complaints', 'p26-t41'),
      ('T', 2020, null::int, 'complaints_registered', 'Drainage', 306::numeric, 'complaints', 'p26-t41'),
      ('T', 2021, null::int, 'complaints_registered', 'Drainage', 283::numeric, 'complaints', 'p26-t41'),
      ('T', 2022, null::int, 'complaints_registered', 'Drainage', 310::numeric, 'complaints', 'p26-t41'),
      ('T', 2023, null::int, 'complaints_registered', 'Drainage', 333::numeric, 'complaints', 'p26-t41'),
      ('T', 2024, null::int, 'complaints_registered', 'Drainage', 349::numeric, 'complaints', 'p26-t41'),
      ('T', 2025, null::int, 'complaints_registered', 'Drainage', 350::numeric, 'complaints', 'p26-t41'),
      (null, 2025, null::int, 'complaints_unassigned_ward', 'Drainage', 1229::numeric, 'complaints', 'p26-t41'),
      ('A', 2023, null::int, 'complaints_closed', null, 1431::numeric, 'complaints', 'p26-t3'),
      ('A', 2023, null::int, 'avg_days_to_close', null, 40::numeric, 'days', 'p26-t3'),
      ('A', 2025, null::int, 'complaints_closed', null, 1972::numeric, 'complaints', 'p26-t3'),
      ('A', 2025, null::int, 'avg_days_to_close', null, 49::numeric, 'days', 'p26-t3'),
      ('B', 2023, null::int, 'complaints_closed', null, 2248::numeric, 'complaints', 'p26-t3'),
      ('B', 2023, null::int, 'avg_days_to_close', null, 46::numeric, 'days', 'p26-t3'),
      ('B', 2025, null::int, 'complaints_closed', null, 2699::numeric, 'complaints', 'p26-t3'),
      ('B', 2025, null::int, 'avg_days_to_close', null, 52::numeric, 'days', 'p26-t3'),
      ('C', 2023, null::int, 'complaints_closed', null, 2983::numeric, 'complaints', 'p26-t3'),
      ('C', 2023, null::int, 'avg_days_to_close', null, 39::numeric, 'days', 'p26-t3'),
      ('C', 2025, null::int, 'complaints_closed', null, 3350::numeric, 'complaints', 'p26-t3'),
      ('C', 2025, null::int, 'avg_days_to_close', null, 26::numeric, 'days', 'p26-t3'),
      ('D', 2023, null::int, 'complaints_closed', null, 3989::numeric, 'complaints', 'p26-t3'),
      ('D', 2023, null::int, 'avg_days_to_close', null, 10::numeric, 'days', 'p26-t3'),
      ('D', 2025, null::int, 'complaints_closed', null, 3564::numeric, 'complaints', 'p26-t3'),
      ('D', 2025, null::int, 'avg_days_to_close', null, 14::numeric, 'days', 'p26-t3'),
      ('E', 2023, null::int, 'complaints_closed', null, 3716::numeric, 'complaints', 'p26-t3'),
      ('E', 2023, null::int, 'avg_days_to_close', null, 50::numeric, 'days', 'p26-t3'),
      ('E', 2025, null::int, 'complaints_closed', null, 4363::numeric, 'complaints', 'p26-t3'),
      ('E', 2025, null::int, 'avg_days_to_close', null, 38::numeric, 'days', 'p26-t3'),
      ('F/N', 2023, null::int, 'complaints_closed', null, 4406::numeric, 'complaints', 'p26-t3'),
      ('F/N', 2023, null::int, 'avg_days_to_close', null, 44::numeric, 'days', 'p26-t3'),
      ('F/N', 2025, null::int, 'complaints_closed', null, 4013::numeric, 'complaints', 'p26-t3'),
      ('F/N', 2025, null::int, 'avg_days_to_close', null, 41::numeric, 'days', 'p26-t3'),
      ('F/S', 2023, null::int, 'complaints_closed', null, 2547::numeric, 'complaints', 'p26-t3'),
      ('F/S', 2023, null::int, 'avg_days_to_close', null, 33::numeric, 'days', 'p26-t3'),
      ('F/S', 2025, null::int, 'complaints_closed', null, 2694::numeric, 'complaints', 'p26-t3'),
      ('F/S', 2025, null::int, 'avg_days_to_close', null, 24::numeric, 'days', 'p26-t3'),
      ('G/N', 2023, null::int, 'complaints_closed', null, 4318::numeric, 'complaints', 'p26-t3'),
      ('G/N', 2023, null::int, 'avg_days_to_close', null, 32::numeric, 'days', 'p26-t3'),
      ('G/N', 2025, null::int, 'complaints_closed', null, 4438::numeric, 'complaints', 'p26-t3'),
      ('G/N', 2025, null::int, 'avg_days_to_close', null, 43::numeric, 'days', 'p26-t3'),
      ('G/S', 2023, null::int, 'complaints_closed', null, 2919::numeric, 'complaints', 'p26-t3'),
      ('G/S', 2023, null::int, 'avg_days_to_close', null, 27::numeric, 'days', 'p26-t3'),
      ('G/S', 2025, null::int, 'complaints_closed', null, 3146::numeric, 'complaints', 'p26-t3'),
      ('G/S', 2025, null::int, 'avg_days_to_close', null, 44::numeric, 'days', 'p26-t3'),
      ('H/E', 2023, null::int, 'complaints_closed', null, 3835::numeric, 'complaints', 'p26-t3'),
      ('H/E', 2023, null::int, 'avg_days_to_close', null, 25::numeric, 'days', 'p26-t3'),
      ('H/E', 2025, null::int, 'complaints_closed', null, 3773::numeric, 'complaints', 'p26-t3'),
      ('H/E', 2025, null::int, 'avg_days_to_close', null, 32::numeric, 'days', 'p26-t3'),
      ('H/W', 2023, null::int, 'complaints_closed', null, 3942::numeric, 'complaints', 'p26-t3'),
      ('H/W', 2023, null::int, 'avg_days_to_close', null, 35::numeric, 'days', 'p26-t3'),
      ('H/W', 2025, null::int, 'complaints_closed', null, 4789::numeric, 'complaints', 'p26-t3'),
      ('H/W', 2025, null::int, 'avg_days_to_close', null, 23::numeric, 'days', 'p26-t3'),
      ('K/E', 2023, null::int, 'complaints_closed', null, 7920::numeric, 'complaints', 'p26-t3'),
      ('K/E', 2023, null::int, 'avg_days_to_close', null, 32::numeric, 'days', 'p26-t3'),
      ('K/E', 2025, null::int, 'complaints_closed', null, 9410::numeric, 'complaints', 'p26-t3'),
      ('K/E', 2025, null::int, 'avg_days_to_close', null, 33::numeric, 'days', 'p26-t3'),
      ('K/W', 2023, null::int, 'complaints_closed', null, 7743::numeric, 'complaints', 'p26-t3'),
      ('K/W', 2023, null::int, 'avg_days_to_close', null, 44::numeric, 'days', 'p26-t3'),
      ('K/W', 2025, null::int, 'complaints_closed', null, 7604::numeric, 'complaints', 'p26-t3'),
      ('K/W', 2025, null::int, 'avg_days_to_close', null, 45::numeric, 'days', 'p26-t3'),
      ('L', 2023, null::int, 'complaints_closed', null, 6274::numeric, 'complaints', 'p26-t3'),
      ('L', 2023, null::int, 'avg_days_to_close', null, 23::numeric, 'days', 'p26-t3'),
      ('L', 2025, null::int, 'complaints_closed', null, 6784::numeric, 'complaints', 'p26-t3'),
      ('L', 2025, null::int, 'avg_days_to_close', null, 33::numeric, 'days', 'p26-t3'),
      ('M/E', 2023, null::int, 'complaints_closed', null, 4199::numeric, 'complaints', 'p26-t3'),
      ('M/E', 2023, null::int, 'avg_days_to_close', null, 27::numeric, 'days', 'p26-t3'),
      ('M/E', 2025, null::int, 'complaints_closed', null, 4385::numeric, 'complaints', 'p26-t3'),
      ('M/E', 2025, null::int, 'avg_days_to_close', null, 19::numeric, 'days', 'p26-t3'),
      ('M/W', 2023, null::int, 'complaints_closed', null, 4004::numeric, 'complaints', 'p26-t3'),
      ('M/W', 2023, null::int, 'avg_days_to_close', null, 19::numeric, 'days', 'p26-t3'),
      ('M/W', 2025, null::int, 'complaints_closed', null, 3970::numeric, 'complaints', 'p26-t3'),
      ('M/W', 2025, null::int, 'avg_days_to_close', null, 20::numeric, 'days', 'p26-t3'),
      ('N', 2023, null::int, 'complaints_closed', null, 6427::numeric, 'complaints', 'p26-t3'),
      ('N', 2023, null::int, 'avg_days_to_close', null, 20::numeric, 'days', 'p26-t3'),
      ('N', 2025, null::int, 'complaints_closed', null, 6093::numeric, 'complaints', 'p26-t3'),
      ('N', 2025, null::int, 'avg_days_to_close', null, 16::numeric, 'days', 'p26-t3'),
      ('P/N', 2023, null::int, 'complaints_closed', null, 3831::numeric, 'complaints', 'p26-t3'),
      ('P/N', 2023, null::int, 'avg_days_to_close', null, 53::numeric, 'days', 'p26-t3'),
      ('P/N', 2025, null::int, 'complaints_closed', null, 7699::numeric, 'complaints', 'p26-t3'),
      ('P/N', 2025, null::int, 'avg_days_to_close', null, 56::numeric, 'days', 'p26-t3'),
      ('P/S', 2023, null::int, 'complaints_closed', null, 3784::numeric, 'complaints', 'p26-t3'),
      ('P/S', 2023, null::int, 'avg_days_to_close', null, 59::numeric, 'days', 'p26-t3'),
      ('P/S', 2025, null::int, 'complaints_closed', null, 5094::numeric, 'complaints', 'p26-t3'),
      ('P/S', 2025, null::int, 'avg_days_to_close', null, 35::numeric, 'days', 'p26-t3'),
      ('R/C', 2023, null::int, 'complaints_closed', null, 5843::numeric, 'complaints', 'p26-t3'),
      ('R/C', 2023, null::int, 'avg_days_to_close', null, 15::numeric, 'days', 'p26-t3'),
      ('R/C', 2025, null::int, 'complaints_closed', null, 5398::numeric, 'complaints', 'p26-t3'),
      ('R/C', 2025, null::int, 'avg_days_to_close', null, 19::numeric, 'days', 'p26-t3'),
      ('R/N', 2023, null::int, 'complaints_closed', null, 2952::numeric, 'complaints', 'p26-t3'),
      ('R/N', 2023, null::int, 'avg_days_to_close', null, 8::numeric, 'days', 'p26-t3'),
      ('R/N', 2025, null::int, 'complaints_closed', null, 3170::numeric, 'complaints', 'p26-t3'),
      ('R/N', 2025, null::int, 'avg_days_to_close', null, 19::numeric, 'days', 'p26-t3'),
      ('R/S', 2023, null::int, 'complaints_closed', null, 5316::numeric, 'complaints', 'p26-t3'),
      ('R/S', 2023, null::int, 'avg_days_to_close', null, 17::numeric, 'days', 'p26-t3'),
      ('R/S', 2025, null::int, 'complaints_closed', null, 5097::numeric, 'complaints', 'p26-t3'),
      ('R/S', 2025, null::int, 'avg_days_to_close', null, 13::numeric, 'days', 'p26-t3'),
      ('S', 2023, null::int, 'complaints_closed', null, 5676::numeric, 'complaints', 'p26-t3'),
      ('S', 2023, null::int, 'avg_days_to_close', null, 50::numeric, 'days', 'p26-t3'),
      ('S', 2025, null::int, 'complaints_closed', null, 12898::numeric, 'complaints', 'p26-t3'),
      ('S', 2025, null::int, 'avg_days_to_close', null, 18::numeric, 'days', 'p26-t3'),
      ('T', 2023, null::int, 'complaints_closed', null, 2609::numeric, 'complaints', 'p26-t3'),
      ('T', 2023, null::int, 'avg_days_to_close', null, 31::numeric, 'days', 'p26-t3'),
      ('T', 2025, null::int, 'complaints_closed', null, 3021::numeric, 'complaints', 'p26-t3'),
      ('T', 2025, null::int, 'avg_days_to_close', null, 7::numeric, 'days', 'p26-t3'),
      (null, 2023, null::int, 'avg_days_to_close', null, 32::numeric, 'days', 'p26-t3'),
      (null, 2025, null::int, 'avg_days_to_close', null, 30::numeric, 'days', 'p26-t3'),
      (null, 2023, null::int, 'complaints_closed', null, 102912::numeric, 'complaints', 'p26-t3'),
      (null, 2025, null::int, 'complaints_closed', null, 119458::numeric, 'complaints', 'p26-t3'),
      ('A', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 93::numeric, 'complaints', 'p26-t40'),
      ('A', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 33::numeric, 'days', 'p26-t40'),
      ('A', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 364::numeric, 'complaints', 'p26-t40'),
      ('A', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 12::numeric, 'days', 'p26-t40'),
      ('B', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 310::numeric, 'complaints', 'p26-t40'),
      ('B', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 16::numeric, 'days', 'p26-t40'),
      ('B', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 553::numeric, 'complaints', 'p26-t40'),
      ('B', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 10::numeric, 'days', 'p26-t40'),
      ('C', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 454::numeric, 'complaints', 'p26-t40'),
      ('C', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 14::numeric, 'days', 'p26-t40'),
      ('C', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 1204::numeric, 'complaints', 'p26-t40'),
      ('C', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 10::numeric, 'days', 'p26-t40'),
      ('D', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 403::numeric, 'complaints', 'p26-t40'),
      ('D', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 43::numeric, 'days', 'p26-t40'),
      ('D', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 796::numeric, 'complaints', 'p26-t40'),
      ('D', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 4::numeric, 'days', 'p26-t40'),
      ('E', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 477::numeric, 'complaints', 'p26-t40'),
      ('E', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 13::numeric, 'days', 'p26-t40'),
      ('E', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 1559::numeric, 'complaints', 'p26-t40'),
      ('E', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 17::numeric, 'days', 'p26-t40'),
      ('F/N', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 514::numeric, 'complaints', 'p26-t40'),
      ('F/N', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 50::numeric, 'days', 'p26-t40'),
      ('F/N', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 1189::numeric, 'complaints', 'p26-t40'),
      ('F/N', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 12::numeric, 'days', 'p26-t40'),
      ('F/S', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 239::numeric, 'complaints', 'p26-t40'),
      ('F/S', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 33::numeric, 'days', 'p26-t40'),
      ('F/S', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 522::numeric, 'complaints', 'p26-t40'),
      ('F/S', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 10::numeric, 'days', 'p26-t40'),
      ('G/N', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 257::numeric, 'complaints', 'p26-t40'),
      ('G/N', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 132::numeric, 'days', 'p26-t40'),
      ('G/N', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 1315::numeric, 'complaints', 'p26-t40'),
      ('G/N', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 8::numeric, 'days', 'p26-t40'),
      ('G/S', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 255::numeric, 'complaints', 'p26-t40'),
      ('G/S', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 13::numeric, 'days', 'p26-t40'),
      ('G/S', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 536::numeric, 'complaints', 'p26-t40'),
      ('G/S', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 9::numeric, 'days', 'p26-t40'),
      ('H/E', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 320::numeric, 'complaints', 'p26-t40'),
      ('H/E', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 13::numeric, 'days', 'p26-t40'),
      ('H/E', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 733::numeric, 'complaints', 'p26-t40'),
      ('H/E', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 9::numeric, 'days', 'p26-t40'),
      ('H/W', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 466::numeric, 'complaints', 'p26-t40'),
      ('H/W', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 25::numeric, 'days', 'p26-t40'),
      ('H/W', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 895::numeric, 'complaints', 'p26-t40'),
      ('H/W', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 8::numeric, 'days', 'p26-t40'),
      ('K/E', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 712::numeric, 'complaints', 'p26-t40'),
      ('K/E', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 12::numeric, 'days', 'p26-t40'),
      ('K/E', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 1197::numeric, 'complaints', 'p26-t40'),
      ('K/E', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 5::numeric, 'days', 'p26-t40'),
      ('K/W', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 917::numeric, 'complaints', 'p26-t40'),
      ('K/W', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 27::numeric, 'days', 'p26-t40'),
      ('K/W', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 2188::numeric, 'complaints', 'p26-t40'),
      ('K/W', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 6::numeric, 'days', 'p26-t40'),
      ('L', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 594::numeric, 'complaints', 'p26-t40'),
      ('L', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 15::numeric, 'days', 'p26-t40'),
      ('L', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 1535::numeric, 'complaints', 'p26-t40'),
      ('L', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 8::numeric, 'days', 'p26-t40'),
      ('M/E', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 399::numeric, 'complaints', 'p26-t40'),
      ('M/E', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 149::numeric, 'days', 'p26-t40'),
      ('M/E', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 885::numeric, 'complaints', 'p26-t40'),
      ('M/E', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 6::numeric, 'days', 'p26-t40'),
      ('M/W', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 458::numeric, 'complaints', 'p26-t40'),
      ('M/W', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 54::numeric, 'days', 'p26-t40'),
      ('M/W', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 778::numeric, 'complaints', 'p26-t40'),
      ('M/W', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 6::numeric, 'days', 'p26-t40'),
      ('N', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 468::numeric, 'complaints', 'p26-t40'),
      ('N', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 45::numeric, 'days', 'p26-t40'),
      ('N', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 836::numeric, 'complaints', 'p26-t40'),
      ('N', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 8::numeric, 'days', 'p26-t40'),
      ('P/N', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 503::numeric, 'complaints', 'p26-t40'),
      ('P/N', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 76::numeric, 'days', 'p26-t40'),
      ('P/N', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 1477::numeric, 'complaints', 'p26-t40'),
      ('P/N', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 6::numeric, 'days', 'p26-t40'),
      ('P/S', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 403::numeric, 'complaints', 'p26-t40'),
      ('P/S', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 56::numeric, 'days', 'p26-t40'),
      ('P/S', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 1615::numeric, 'complaints', 'p26-t40'),
      ('P/S', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 8::numeric, 'days', 'p26-t40'),
      ('R/C', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 710::numeric, 'complaints', 'p26-t40'),
      ('R/C', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 26::numeric, 'days', 'p26-t40'),
      ('R/C', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 956::numeric, 'complaints', 'p26-t40'),
      ('R/C', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 5::numeric, 'days', 'p26-t40'),
      ('R/N', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 290::numeric, 'complaints', 'p26-t40'),
      ('R/N', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 23::numeric, 'days', 'p26-t40'),
      ('R/N', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 699::numeric, 'complaints', 'p26-t40'),
      ('R/N', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 4::numeric, 'days', 'p26-t40'),
      ('R/S', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 460::numeric, 'complaints', 'p26-t40'),
      ('R/S', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 26::numeric, 'days', 'p26-t40'),
      ('R/S', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 1105::numeric, 'complaints', 'p26-t40'),
      ('R/S', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 6::numeric, 'days', 'p26-t40'),
      ('S', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 389::numeric, 'complaints', 'p26-t40'),
      ('S', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 79::numeric, 'days', 'p26-t40'),
      ('S', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 3032::numeric, 'complaints', 'p26-t40'),
      ('S', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 8::numeric, 'days', 'p26-t40'),
      ('T', 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 171::numeric, 'complaints', 'p26-t40'),
      ('T', 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 81::numeric, 'days', 'p26-t40'),
      ('T', 2025, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 405::numeric, 'complaints', 'p26-t40'),
      ('T', 2025, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 4::numeric, 'days', 'p26-t40'),
      (null, 2021, null::int, 'avg_days_to_close', 'Solid Waste Management (SWM)', 40::numeric, 'days', 'p26-t40'),
      (null, 2021, null::int, 'complaints_closed', 'Solid Waste Management (SWM)', 10262::numeric, 'complaints', 'p26-t40'),
      ('A', 2021, null::int, 'complaints_closed', 'Drainage', 202::numeric, 'complaints', 'p26-t42'),
      ('A', 2021, null::int, 'avg_days_to_close', 'Drainage', 53::numeric, 'days', 'p26-t42'),
      ('A', 2025, null::int, 'complaints_closed', 'Drainage', 255::numeric, 'complaints', 'p26-t42'),
      ('A', 2025, null::int, 'avg_days_to_close', 'Drainage', 56::numeric, 'days', 'p26-t42'),
      ('B', 2021, null::int, 'complaints_closed', 'Drainage', 523::numeric, 'complaints', 'p26-t42'),
      ('B', 2021, null::int, 'avg_days_to_close', 'Drainage', 13::numeric, 'days', 'p26-t42'),
      ('B', 2025, null::int, 'complaints_closed', 'Drainage', 372::numeric, 'complaints', 'p26-t42'),
      ('B', 2025, null::int, 'avg_days_to_close', 'Drainage', 67::numeric, 'days', 'p26-t42'),
      ('C', 2021, null::int, 'complaints_closed', 'Drainage', 466::numeric, 'complaints', 'p26-t42'),
      ('C', 2021, null::int, 'avg_days_to_close', 'Drainage', 8::numeric, 'days', 'p26-t42'),
      ('C', 2025, null::int, 'complaints_closed', 'Drainage', 543::numeric, 'complaints', 'p26-t42'),
      ('C', 2025, null::int, 'avg_days_to_close', 'Drainage', 28::numeric, 'days', 'p26-t42'),
      ('D', 2021, null::int, 'complaints_closed', 'Drainage', 515::numeric, 'complaints', 'p26-t42'),
      ('D', 2021, null::int, 'avg_days_to_close', 'Drainage', 48::numeric, 'days', 'p26-t42'),
      ('D', 2025, null::int, 'complaints_closed', 'Drainage', 699::numeric, 'complaints', 'p26-t42'),
      ('D', 2025, null::int, 'avg_days_to_close', 'Drainage', 8::numeric, 'days', 'p26-t42'),
      ('E', 2021, null::int, 'complaints_closed', 'Drainage', 371::numeric, 'complaints', 'p26-t42'),
      ('E', 2021, null::int, 'avg_days_to_close', 'Drainage', 10::numeric, 'days', 'p26-t42'),
      ('E', 2025, null::int, 'complaints_closed', 'Drainage', 43::numeric, 'complaints', 'p26-t42'),
      ('E', 2025, null::int, 'avg_days_to_close', 'Drainage', 49::numeric, 'days', 'p26-t42'),
      ('F/N', 2021, null::int, 'complaints_closed', 'Drainage', 295::numeric, 'complaints', 'p26-t42'),
      ('F/N', 2021, null::int, 'avg_days_to_close', 'Drainage', 15::numeric, 'days', 'p26-t42'),
      ('F/N', 2025, null::int, 'complaints_closed', 'Drainage', 458::numeric, 'complaints', 'p26-t42'),
      ('F/N', 2025, null::int, 'avg_days_to_close', 'Drainage', 49::numeric, 'days', 'p26-t42'),
      ('F/S', 2021, null::int, 'complaints_closed', 'Drainage', 378::numeric, 'complaints', 'p26-t42'),
      ('F/S', 2021, null::int, 'avg_days_to_close', 'Drainage', 10::numeric, 'days', 'p26-t42'),
      ('F/S', 2025, null::int, 'complaints_closed', 'Drainage', 376::numeric, 'complaints', 'p26-t42'),
      ('F/S', 2025, null::int, 'avg_days_to_close', 'Drainage', 10::numeric, 'days', 'p26-t42'),
      ('G/N', 2021, null::int, 'complaints_closed', 'Drainage', 476::numeric, 'complaints', 'p26-t42'),
      ('G/N', 2021, null::int, 'avg_days_to_close', 'Drainage', 178::numeric, 'days', 'p26-t42'),
      ('G/N', 2025, null::int, 'complaints_closed', 'Drainage', 738::numeric, 'complaints', 'p26-t42'),
      ('G/N', 2025, null::int, 'avg_days_to_close', 'Drainage', 76::numeric, 'days', 'p26-t42'),
      ('G/S', 2021, null::int, 'complaints_closed', 'Drainage', 302::numeric, 'complaints', 'p26-t42'),
      ('G/S', 2021, null::int, 'avg_days_to_close', 'Drainage', 24::numeric, 'days', 'p26-t42'),
      ('G/S', 2025, null::int, 'complaints_closed', 'Drainage', 550::numeric, 'complaints', 'p26-t42'),
      ('G/S', 2025, null::int, 'avg_days_to_close', 'Drainage', 109::numeric, 'days', 'p26-t42'),
      ('H/E', 2021, null::int, 'complaints_closed', 'Drainage', 528::numeric, 'complaints', 'p26-t42'),
      ('H/E', 2021, null::int, 'avg_days_to_close', 'Drainage', 14::numeric, 'days', 'p26-t42'),
      ('H/E', 2025, null::int, 'complaints_closed', 'Drainage', 686::numeric, 'complaints', 'p26-t42'),
      ('H/E', 2025, null::int, 'avg_days_to_close', 'Drainage', 40::numeric, 'days', 'p26-t42'),
      ('H/W', 2021, null::int, 'complaints_closed', 'Drainage', 584::numeric, 'complaints', 'p26-t42'),
      ('H/W', 2021, null::int, 'avg_days_to_close', 'Drainage', 28::numeric, 'days', 'p26-t42'),
      ('H/W', 2025, null::int, 'complaints_closed', 'Drainage', 642::numeric, 'complaints', 'p26-t42'),
      ('H/W', 2025, null::int, 'avg_days_to_close', 'Drainage', 18::numeric, 'days', 'p26-t42'),
      ('K/E', 2021, null::int, 'complaints_closed', 'Drainage', 834::numeric, 'complaints', 'p26-t42'),
      ('K/E', 2021, null::int, 'avg_days_to_close', 'Drainage', 75::numeric, 'days', 'p26-t42'),
      ('K/E', 2025, null::int, 'complaints_closed', 'Drainage', 967::numeric, 'complaints', 'p26-t42'),
      ('K/E', 2025, null::int, 'avg_days_to_close', 'Drainage', 50::numeric, 'days', 'p26-t42'),
      ('K/W', 2021, null::int, 'complaints_closed', 'Drainage', 1203::numeric, 'complaints', 'p26-t42'),
      ('K/W', 2021, null::int, 'avg_days_to_close', 'Drainage', 39::numeric, 'days', 'p26-t42'),
      ('K/W', 2025, null::int, 'complaints_closed', 'Drainage', 1067::numeric, 'complaints', 'p26-t42'),
      ('K/W', 2025, null::int, 'avg_days_to_close', 'Drainage', 83::numeric, 'days', 'p26-t42'),
      ('L', 2021, null::int, 'complaints_closed', 'Drainage', 764::numeric, 'complaints', 'p26-t42'),
      ('L', 2021, null::int, 'avg_days_to_close', 'Drainage', 39::numeric, 'days', 'p26-t42'),
      ('L', 2025, null::int, 'complaints_closed', 'Drainage', 903::numeric, 'complaints', 'p26-t42'),
      ('L', 2025, null::int, 'avg_days_to_close', 'Drainage', 19::numeric, 'days', 'p26-t42'),
      ('M/E', 2021, null::int, 'complaints_closed', 'Drainage', 467::numeric, 'complaints', 'p26-t42'),
      ('M/E', 2021, null::int, 'avg_days_to_close', 'Drainage', 53::numeric, 'days', 'p26-t42'),
      ('M/E', 2025, null::int, 'complaints_closed', 'Drainage', 841::numeric, 'complaints', 'p26-t42'),
      ('M/E', 2025, null::int, 'avg_days_to_close', 'Drainage', 16::numeric, 'days', 'p26-t42'),
      ('M/W', 2021, null::int, 'complaints_closed', 'Drainage', 671::numeric, 'complaints', 'p26-t42'),
      ('M/W', 2021, null::int, 'avg_days_to_close', 'Drainage', 60::numeric, 'days', 'p26-t42'),
      ('M/W', 2025, null::int, 'complaints_closed', 'Drainage', 623::numeric, 'complaints', 'p26-t42'),
      ('M/W', 2025, null::int, 'avg_days_to_close', 'Drainage', 22::numeric, 'days', 'p26-t42'),
      ('N', 2021, null::int, 'complaints_closed', 'Drainage', 555::numeric, 'complaints', 'p26-t42'),
      ('N', 2021, null::int, 'avg_days_to_close', 'Drainage', 50::numeric, 'days', 'p26-t42'),
      ('N', 2025, null::int, 'complaints_closed', 'Drainage', 729::numeric, 'complaints', 'p26-t42'),
      ('N', 2025, null::int, 'avg_days_to_close', 'Drainage', 14::numeric, 'days', 'p26-t42'),
      ('P/N', 2021, null::int, 'complaints_closed', 'Drainage', 724::numeric, 'complaints', 'p26-t42'),
      ('P/N', 2021, null::int, 'avg_days_to_close', 'Drainage', 37::numeric, 'days', 'p26-t42'),
      ('P/N', 2025, null::int, 'complaints_closed', 'Drainage', 1152::numeric, 'complaints', 'p26-t42'),
      ('P/N', 2025, null::int, 'avg_days_to_close', 'Drainage', 73::numeric, 'days', 'p26-t42'),
      ('P/S', 2021, null::int, 'complaints_closed', 'Drainage', 390::numeric, 'complaints', 'p26-t42'),
      ('P/S', 2021, null::int, 'avg_days_to_close', 'Drainage', 61::numeric, 'days', 'p26-t42'),
      ('P/S', 2025, null::int, 'complaints_closed', 'Drainage', 603::numeric, 'complaints', 'p26-t42'),
      ('P/S', 2025, null::int, 'avg_days_to_close', 'Drainage', 59::numeric, 'days', 'p26-t42'),
      ('R/C', 2021, null::int, 'complaints_closed', 'Drainage', 691::numeric, 'complaints', 'p26-t42'),
      ('R/C', 2021, null::int, 'avg_days_to_close', 'Drainage', 37::numeric, 'days', 'p26-t42'),
      ('R/C', 2025, null::int, 'complaints_closed', 'Drainage', 559::numeric, 'complaints', 'p26-t42'),
      ('R/C', 2025, null::int, 'avg_days_to_close', 'Drainage', 22::numeric, 'days', 'p26-t42'),
      ('R/N', 2021, null::int, 'complaints_closed', 'Drainage', 319::numeric, 'complaints', 'p26-t42'),
      ('R/N', 2021, null::int, 'avg_days_to_close', 'Drainage', 33::numeric, 'days', 'p26-t42'),
      ('R/N', 2025, null::int, 'complaints_closed', 'Drainage', 339::numeric, 'complaints', 'p26-t42'),
      ('R/N', 2025, null::int, 'avg_days_to_close', 'Drainage', 26::numeric, 'days', 'p26-t42'),
      ('R/S', 2021, null::int, 'complaints_closed', 'Drainage', 633::numeric, 'complaints', 'p26-t42'),
      ('R/S', 2021, null::int, 'avg_days_to_close', 'Drainage', 25::numeric, 'days', 'p26-t42'),
      ('R/S', 2025, null::int, 'complaints_closed', 'Drainage', 657::numeric, 'complaints', 'p26-t42'),
      ('R/S', 2025, null::int, 'avg_days_to_close', 'Drainage', 10::numeric, 'days', 'p26-t42'),
      ('S', 2021, null::int, 'complaints_closed', 'Drainage', 496::numeric, 'complaints', 'p26-t42'),
      ('S', 2021, null::int, 'avg_days_to_close', 'Drainage', 50::numeric, 'days', 'p26-t42'),
      ('S', 2025, null::int, 'complaints_closed', 'Drainage', 911::numeric, 'complaints', 'p26-t42'),
      ('S', 2025, null::int, 'avg_days_to_close', 'Drainage', 33::numeric, 'days', 'p26-t42'),
      ('T', 2021, null::int, 'complaints_closed', 'Drainage', 275::numeric, 'complaints', 'p26-t42'),
      ('T', 2021, null::int, 'avg_days_to_close', 'Drainage', 80::numeric, 'days', 'p26-t42'),
      ('T', 2025, null::int, 'complaints_closed', 'Drainage', 350::numeric, 'complaints', 'p26-t42'),
      ('T', 2025, null::int, 'avg_days_to_close', 'Drainage', 7::numeric, 'days', 'p26-t42'),
      (null, 2021, null::int, 'avg_days_to_close', 'Drainage', 44::numeric, 'days', 'p26-t42'),
      (null, 2021, null::int, 'complaints_closed', 'Drainage', 12662::numeric, 'complaints', 'p26-t42'),
      (null, 2016, null::int, 'complaints_registered', 'Buildings', 16257::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Buildings', 19267::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Buildings', 21014::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Buildings', 20317::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Buildings', 14712::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Buildings', 17063::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Buildings', 16883::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Buildings', 14572::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Buildings', 14451::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Buildings', 16654::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Colony Officer', 1954::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Colony Officer', 1245::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Colony Officer', 1437::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Colony Officer', 1196::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Colony Officer', 1045::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Colony Officer', 1305::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Colony Officer', 981::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Colony Officer', 1056::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Colony Officer', 823::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Colony Officer', 962::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Drainage', 12269::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Drainage', 15940::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Drainage', 20641::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Drainage', 24267::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Drainage', 15508::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Drainage', 14006::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Drainage', 17121::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Drainage', 18752::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Drainage', 15701::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Drainage', 16415::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Estate', 560::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Estate', 407::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Estate', 588::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Estate', 623::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Estate', 645::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Estate', 538::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Estate', 661::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Estate', 553::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Estate', 949::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Estate', 1097::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Garden', 1658::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Garden', 1844::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Garden', 2936::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Garden', 3367::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Garden', 4522::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Garden', 3323::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Garden', 3529::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Garden', 3644::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Garden', 3293::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Garden', 3612::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'License', 8368::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'License', 10372::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'License', 14203::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'License', 14465::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'License', 9694::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'License', 10814::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'License', 13439::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'License', 13672::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'License', 12275::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'License', 17435::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'MCGM Related', 862::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'MCGM Related', 889::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'MCGM Related', 877::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'MCGM Related', 1103::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'MCGM Related', 760::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'MCGM Related', 647::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'MCGM Related', 735::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'MCGM Related', 759::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'MCGM Related', 765::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'MCGM Related', 702::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Medical Officer Health (MOH)', 1111::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Medical Officer Health (MOH)', 1595::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Medical Officer Health (MOH)', 1743::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Medical Officer Health (MOH)', 1480::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Medical Officer Health (MOH)', 1343::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Medical Officer Health (MOH)', 1087::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Medical Officer Health (MOH)', 1384::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Medical Officer Health (MOH)', 1652::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Medical Officer Health (MOH)', 1752::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Medical Officer Health (MOH)', 1727::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Miscellaneous issues in Civic', 1856::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Miscellaneous issues in Civic', 2849::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Miscellaneous issues in Civic', 2653::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Miscellaneous issues in Civic', 2057::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Miscellaneous issues in Civic', 952::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Miscellaneous issues in Civic', 1383::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Miscellaneous issues in Civic', 1599::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Miscellaneous issues in Civic', 2533::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Miscellaneous issues in Civic', 3233::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Miscellaneous issues in Civic', 1679::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Pest control', 6078::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Pest control', 5529::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Pest control', 6703::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Pest control', 7501::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Pest control', 10971::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Pest control', 7785::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Pest control', 8037::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Pest control', 8328::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Pest control', 8721::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Pest control', 10898::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Pollution', 220::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Pollution', 215::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Pollution', 286::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Pollution', 269::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Pollution', 220::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Pollution', 424::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Pollution', 292::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Pollution', 760::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Pollution', 586::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Pollution', 1389::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Roads', 13475::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Roads', 11606::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Roads', 13458::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Roads', 15239::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Roads', 6908::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Roads', 7475::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Roads', 11161::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Roads', 10549::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Roads', 9800::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Roads', 11351::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'School', 74::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'School', 42::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'School', 58::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'School', 78::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'School', 31::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'School', 43::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'School', 70::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'School', 72::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'School', 73::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'School', 74::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Shop and Establishment', 561::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Shop and Establishment', 1478::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Shop and Establishment', 878::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Shop and Establishment', 778::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Shop and Establishment', 986::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Shop and Establishment', 763::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Shop and Establishment', 647::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Shop and Establishment', 695::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Shop and Establishment', 612::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Shop and Establishment', 676::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 7330::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 10144::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 14494::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 17116::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 11595::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 11056::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 12351::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 24690::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 25031::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Solid Waste Management (SWM)', 27938::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Storm Water Drainage', 1386::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Storm Water Drainage', 1532::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Storm Water Drainage', 1548::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Storm Water Drainage', 2155::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Storm Water Drainage', 1409::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Storm Water Drainage', 1068::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Storm Water Drainage', 1550::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Storm Water Drainage', 2713::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Storm Water Drainage', 2304::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Storm Water Drainage', 2600::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Toilet', 290::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Toilet', 416::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Toilet', 494::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Toilet', 627::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Toilet', 618::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Toilet', 489::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Toilet', 531::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Toilet', 544::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Toilet', 505::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Toilet', 679::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', 'Water Supply', 7246::numeric, 'complaints', 'p26-t1'),
      (null, 2017, null::int, 'complaints_registered', 'Water Supply', 6959::numeric, 'complaints', 'p26-t1'),
      (null, 2018, null::int, 'complaints_registered', 'Water Supply', 12647::numeric, 'complaints', 'p26-t1'),
      (null, 2019, null::int, 'complaints_registered', 'Water Supply', 15507::numeric, 'complaints', 'p26-t1'),
      (null, 2020, null::int, 'complaints_registered', 'Water Supply', 11855::numeric, 'complaints', 'p26-t1'),
      (null, 2021, null::int, 'complaints_registered', 'Water Supply', 10981::numeric, 'complaints', 'p26-t1'),
      (null, 2022, null::int, 'complaints_registered', 'Water Supply', 13097::numeric, 'complaints', 'p26-t1'),
      (null, 2023, null::int, 'complaints_registered', 'Water Supply', 14752::numeric, 'complaints', 'p26-t1'),
      (null, 2024, null::int, 'complaints_registered', 'Water Supply', 14522::numeric, 'complaints', 'p26-t1'),
      (null, 2025, null::int, 'complaints_registered', 'Water Supply', 14178::numeric, 'complaints', 'p26-t1'),
      (null, 2016, null::int, 'complaints_registered', null, 81555::numeric, 'complaints', 'p26-t43'),
      (null, 2017, null::int, 'complaints_registered', null, 92329::numeric, 'complaints', 'p26-t43'),
      (null, 2018, null::int, 'complaints_registered', null, 116658::numeric, 'complaints', 'p26-t43'),
      (null, 2019, null::int, 'complaints_registered', null, 128145::numeric, 'complaints', 'p26-t43'),
      (null, 2020, null::int, 'complaints_registered', null, 93774::numeric, 'complaints', 'p26-t43'),
      (null, 2021, null::int, 'complaints_registered', null, 90250::numeric, 'complaints', 'p26-t43'),
      (null, 2022, null::int, 'complaints_registered', null, 104068::numeric, 'complaints', 'p26-t43'),
      (null, 2023, null::int, 'complaints_registered', null, 120296::numeric, 'complaints', 'p26-t43'),
      (null, 2024, null::int, 'complaints_registered', null, 115396::numeric, 'complaints', 'p26-t43'),
      (null, 2025, null::int, 'complaints_registered', null, 130066::numeric, 'complaints', 'p26-t43'),
      ('A', 2021, null::int, 'waste_tonnes_per_day', null, 152::numeric, 'MT/day', 'p26-t37'),
      ('A', 2022, null::int, 'waste_tonnes_per_day', null, 174::numeric, 'MT/day', 'p26-t37'),
      ('A', 2023, null::int, 'waste_tonnes_per_day', null, 114::numeric, 'MT/day', 'p26-t37'),
      ('A', 2024, null::int, 'waste_tonnes_per_day', null, 114::numeric, 'MT/day', 'p26-t37'),
      ('A', 2025, null::int, 'waste_tonnes_per_day', null, 125::numeric, 'MT/day', 'p26-t37'),
      ('B', 2021, null::int, 'waste_tonnes_per_day', null, 92::numeric, 'MT/day', 'p26-t37'),
      ('B', 2022, null::int, 'waste_tonnes_per_day', null, 112::numeric, 'MT/day', 'p26-t37'),
      ('B', 2023, null::int, 'waste_tonnes_per_day', null, 70::numeric, 'MT/day', 'p26-t37'),
      ('B', 2024, null::int, 'waste_tonnes_per_day', null, 73::numeric, 'MT/day', 'p26-t37'),
      ('B', 2025, null::int, 'waste_tonnes_per_day', null, 73::numeric, 'MT/day', 'p26-t37'),
      ('C', 2021, null::int, 'waste_tonnes_per_day', null, 107::numeric, 'MT/day', 'p26-t37'),
      ('C', 2022, null::int, 'waste_tonnes_per_day', null, 128::numeric, 'MT/day', 'p26-t37'),
      ('C', 2023, null::int, 'waste_tonnes_per_day', null, 117::numeric, 'MT/day', 'p26-t37'),
      ('C', 2024, null::int, 'waste_tonnes_per_day', null, 111::numeric, 'MT/day', 'p26-t37'),
      ('C', 2025, null::int, 'waste_tonnes_per_day', null, 116::numeric, 'MT/day', 'p26-t37'),
      ('D', 2021, null::int, 'waste_tonnes_per_day', null, 197::numeric, 'MT/day', 'p26-t37'),
      ('D', 2022, null::int, 'waste_tonnes_per_day', null, 203::numeric, 'MT/day', 'p26-t37'),
      ('D', 2023, null::int, 'waste_tonnes_per_day', null, 96::numeric, 'MT/day', 'p26-t37'),
      ('D', 2024, null::int, 'waste_tonnes_per_day', null, 97::numeric, 'MT/day', 'p26-t37'),
      ('D', 2025, null::int, 'waste_tonnes_per_day', null, 104::numeric, 'MT/day', 'p26-t37'),
      ('E', 2021, null::int, 'waste_tonnes_per_day', null, 270::numeric, 'MT/day', 'p26-t37'),
      ('E', 2022, null::int, 'waste_tonnes_per_day', null, 253::numeric, 'MT/day', 'p26-t37'),
      ('E', 2023, null::int, 'waste_tonnes_per_day', null, 132::numeric, 'MT/day', 'p26-t37'),
      ('E', 2024, null::int, 'waste_tonnes_per_day', null, 126::numeric, 'MT/day', 'p26-t37'),
      ('E', 2025, null::int, 'waste_tonnes_per_day', null, 132::numeric, 'MT/day', 'p26-t37'),
      ('F/S', 2021, null::int, 'waste_tonnes_per_day', null, 160::numeric, 'MT/day', 'p26-t37'),
      ('F/S', 2022, null::int, 'waste_tonnes_per_day', null, 265::numeric, 'MT/day', 'p26-t37'),
      ('F/S', 2023, null::int, 'waste_tonnes_per_day', null, 107::numeric, 'MT/day', 'p26-t37'),
      ('F/S', 2024, null::int, 'waste_tonnes_per_day', null, 105::numeric, 'MT/day', 'p26-t37'),
      ('F/S', 2025, null::int, 'waste_tonnes_per_day', null, 116::numeric, 'MT/day', 'p26-t37'),
      ('F/N', 2021, null::int, 'waste_tonnes_per_day', null, 236::numeric, 'MT/day', 'p26-t37'),
      ('F/N', 2022, null::int, 'waste_tonnes_per_day', null, 163::numeric, 'MT/day', 'p26-t37'),
      ('F/N', 2023, null::int, 'waste_tonnes_per_day', null, 156::numeric, 'MT/day', 'p26-t37'),
      ('F/N', 2024, null::int, 'waste_tonnes_per_day', null, 160::numeric, 'MT/day', 'p26-t37'),
      ('F/N', 2025, null::int, 'waste_tonnes_per_day', null, 167::numeric, 'MT/day', 'p26-t37'),
      ('G/S', 2021, null::int, 'waste_tonnes_per_day', null, 187::numeric, 'MT/day', 'p26-t37'),
      ('G/S', 2022, null::int, 'waste_tonnes_per_day', null, 212::numeric, 'MT/day', 'p26-t37'),
      ('G/S', 2023, null::int, 'waste_tonnes_per_day', null, 111::numeric, 'MT/day', 'p26-t37'),
      ('G/S', 2024, null::int, 'waste_tonnes_per_day', null, 110::numeric, 'MT/day', 'p26-t37'),
      ('G/S', 2025, null::int, 'waste_tonnes_per_day', null, 107::numeric, 'MT/day', 'p26-t37'),
      ('G/N', 2021, null::int, 'waste_tonnes_per_day', null, 442::numeric, 'MT/day', 'p26-t37'),
      ('G/N', 2022, null::int, 'waste_tonnes_per_day', null, 459::numeric, 'MT/day', 'p26-t37'),
      ('G/N', 2023, null::int, 'waste_tonnes_per_day', null, 225::numeric, 'MT/day', 'p26-t37'),
      ('G/N', 2024, null::int, 'waste_tonnes_per_day', null, 217::numeric, 'MT/day', 'p26-t37'),
      ('G/N', 2025, null::int, 'waste_tonnes_per_day', null, 266::numeric, 'MT/day', 'p26-t37'),
      ('H/E', 2021, null::int, 'waste_tonnes_per_day', null, 251::numeric, 'MT/day', 'p26-t37'),
      ('H/E', 2022, null::int, 'waste_tonnes_per_day', null, 314::numeric, 'MT/day', 'p26-t37'),
      ('H/E', 2023, null::int, 'waste_tonnes_per_day', null, 168::numeric, 'MT/day', 'p26-t37'),
      ('H/E', 2024, null::int, 'waste_tonnes_per_day', null, 169::numeric, 'MT/day', 'p26-t37'),
      ('H/E', 2025, null::int, 'waste_tonnes_per_day', null, 174::numeric, 'MT/day', 'p26-t37'),
      ('H/W', 2021, null::int, 'waste_tonnes_per_day', null, 229::numeric, 'MT/day', 'p26-t37'),
      ('H/W', 2022, null::int, 'waste_tonnes_per_day', null, 243::numeric, 'MT/day', 'p26-t37'),
      ('H/W', 2023, null::int, 'waste_tonnes_per_day', null, 175::numeric, 'MT/day', 'p26-t37'),
      ('H/W', 2024, null::int, 'waste_tonnes_per_day', null, 188::numeric, 'MT/day', 'p26-t37'),
      ('H/W', 2025, null::int, 'waste_tonnes_per_day', null, 194::numeric, 'MT/day', 'p26-t37'),
      ('K/E', 2021, null::int, 'waste_tonnes_per_day', null, 396::numeric, 'MT/day', 'p26-t37'),
      ('K/E', 2022, null::int, 'waste_tonnes_per_day', null, 441::numeric, 'MT/day', 'p26-t37'),
      ('K/E', 2023, null::int, 'waste_tonnes_per_day', null, 302::numeric, 'MT/day', 'p26-t37'),
      ('K/E', 2024, null::int, 'waste_tonnes_per_day', null, 313::numeric, 'MT/day', 'p26-t37'),
      ('K/E', 2025, null::int, 'waste_tonnes_per_day', null, 318::numeric, 'MT/day', 'p26-t37'),
      ('K/W', 2021, null::int, 'waste_tonnes_per_day', null, 387::numeric, 'MT/day', 'p26-t37'),
      ('K/W', 2022, null::int, 'waste_tonnes_per_day', null, 405::numeric, 'MT/day', 'p26-t37'),
      ('K/W', 2023, null::int, 'waste_tonnes_per_day', null, 341::numeric, 'MT/day', 'p26-t37'),
      ('K/W', 2024, null::int, 'waste_tonnes_per_day', null, 308::numeric, 'MT/day', 'p26-t37'),
      ('K/W', 2025, null::int, 'waste_tonnes_per_day', null, 311::numeric, 'MT/day', 'p26-t37'),
      ('P/S', 2021, null::int, 'waste_tonnes_per_day', null, 250::numeric, 'MT/day', 'p26-t37'),
      ('P/S', 2022, null::int, 'waste_tonnes_per_day', null, 267::numeric, 'MT/day', 'p26-t37'),
      ('P/S', 2023, null::int, 'waste_tonnes_per_day', null, 183::numeric, 'MT/day', 'p26-t37'),
      ('P/S', 2024, null::int, 'waste_tonnes_per_day', null, 192::numeric, 'MT/day', 'p26-t37'),
      ('P/S', 2025, null::int, 'waste_tonnes_per_day', null, 191::numeric, 'MT/day', 'p26-t37'),
      ('P/N', 2021, null::int, 'waste_tonnes_per_day', null, 393::numeric, 'MT/day', 'p26-t37'),
      ('P/N', 2022, null::int, 'waste_tonnes_per_day', null, 435::numeric, 'MT/day', 'p26-t37'),
      ('P/N', 2023, null::int, 'waste_tonnes_per_day', null, 322::numeric, 'MT/day', 'p26-t37'),
      ('P/N', 2024, null::int, 'waste_tonnes_per_day', null, 310::numeric, 'MT/day', 'p26-t37'),
      ('P/N', 2025, null::int, 'waste_tonnes_per_day', null, 304::numeric, 'MT/day', 'p26-t37'),
      ('R/S', 2021, null::int, 'waste_tonnes_per_day', null, 267::numeric, 'MT/day', 'p26-t37'),
      ('R/S', 2022, null::int, 'waste_tonnes_per_day', null, 268::numeric, 'MT/day', 'p26-t37'),
      ('R/S', 2023, null::int, 'waste_tonnes_per_day', null, 157::numeric, 'MT/day', 'p26-t37'),
      ('R/S', 2024, null::int, 'waste_tonnes_per_day', null, 160::numeric, 'MT/day', 'p26-t37'),
      ('R/S', 2025, null::int, 'waste_tonnes_per_day', null, 162::numeric, 'MT/day', 'p26-t37'),
      ('R/C', 2021, null::int, 'waste_tonnes_per_day', null, 245::numeric, 'MT/day', 'p26-t37'),
      ('R/C', 2022, null::int, 'waste_tonnes_per_day', null, 264::numeric, 'MT/day', 'p26-t37'),
      ('R/C', 2023, null::int, 'waste_tonnes_per_day', null, 167::numeric, 'MT/day', 'p26-t37'),
      ('R/C', 2024, null::int, 'waste_tonnes_per_day', null, 168::numeric, 'MT/day', 'p26-t37'),
      ('R/C', 2025, null::int, 'waste_tonnes_per_day', null, 170::numeric, 'MT/day', 'p26-t37'),
      ('R/N', 2021, null::int, 'waste_tonnes_per_day', null, 153::numeric, 'MT/day', 'p26-t37'),
      ('R/N', 2022, null::int, 'waste_tonnes_per_day', null, 163::numeric, 'MT/day', 'p26-t37'),
      ('R/N', 2023, null::int, 'waste_tonnes_per_day', null, 108::numeric, 'MT/day', 'p26-t37'),
      ('R/N', 2024, null::int, 'waste_tonnes_per_day', null, 110::numeric, 'MT/day', 'p26-t37'),
      ('R/N', 2025, null::int, 'waste_tonnes_per_day', null, 118::numeric, 'MT/day', 'p26-t37'),
      ('L', 2021, null::int, 'waste_tonnes_per_day', null, 446::numeric, 'MT/day', 'p26-t37'),
      ('L', 2022, null::int, 'waste_tonnes_per_day', null, 491::numeric, 'MT/day', 'p26-t37'),
      ('L', 2023, null::int, 'waste_tonnes_per_day', null, 331::numeric, 'MT/day', 'p26-t37'),
      ('L', 2024, null::int, 'waste_tonnes_per_day', null, 357::numeric, 'MT/day', 'p26-t37'),
      ('L', 2025, null::int, 'waste_tonnes_per_day', null, 368::numeric, 'MT/day', 'p26-t37'),
      ('M/E', 2021, null::int, 'waste_tonnes_per_day', null, 354::numeric, 'MT/day', 'p26-t37'),
      ('M/E', 2022, null::int, 'waste_tonnes_per_day', null, 323::numeric, 'MT/day', 'p26-t37'),
      ('M/E', 2023, null::int, 'waste_tonnes_per_day', null, 367::numeric, 'MT/day', 'p26-t37'),
      ('M/E', 2024, null::int, 'waste_tonnes_per_day', null, 389::numeric, 'MT/day', 'p26-t37'),
      ('M/E', 2025, null::int, 'waste_tonnes_per_day', null, 398::numeric, 'MT/day', 'p26-t37'),
      ('M/W', 2021, null::int, 'waste_tonnes_per_day', null, 197::numeric, 'MT/day', 'p26-t37'),
      ('M/W', 2022, null::int, 'waste_tonnes_per_day', null, 208::numeric, 'MT/day', 'p26-t37'),
      ('M/W', 2023, null::int, 'waste_tonnes_per_day', null, 218::numeric, 'MT/day', 'p26-t37'),
      ('M/W', 2024, null::int, 'waste_tonnes_per_day', null, 226::numeric, 'MT/day', 'p26-t37'),
      ('M/W', 2025, null::int, 'waste_tonnes_per_day', null, 235::numeric, 'MT/day', 'p26-t37'),
      ('N', 2021, null::int, 'waste_tonnes_per_day', null, 173::numeric, 'MT/day', 'p26-t37'),
      ('N', 2022, null::int, 'waste_tonnes_per_day', null, 182::numeric, 'MT/day', 'p26-t37'),
      ('N', 2023, null::int, 'waste_tonnes_per_day', null, 186::numeric, 'MT/day', 'p26-t37'),
      ('N', 2024, null::int, 'waste_tonnes_per_day', null, 191::numeric, 'MT/day', 'p26-t37'),
      ('N', 2025, null::int, 'waste_tonnes_per_day', null, 192::numeric, 'MT/day', 'p26-t37'),
      ('S', 2021, null::int, 'waste_tonnes_per_day', null, 265::numeric, 'MT/day', 'p26-t37'),
      ('S', 2022, null::int, 'waste_tonnes_per_day', null, 263::numeric, 'MT/day', 'p26-t37'),
      ('S', 2023, null::int, 'waste_tonnes_per_day', null, 268::numeric, 'MT/day', 'p26-t37'),
      ('S', 2024, null::int, 'waste_tonnes_per_day', null, 268::numeric, 'MT/day', 'p26-t37'),
      ('S', 2025, null::int, 'waste_tonnes_per_day', null, 277::numeric, 'MT/day', 'p26-t37'),
      ('T', 2021, null::int, 'waste_tonnes_per_day', null, 149::numeric, 'MT/day', 'p26-t37'),
      ('T', 2022, null::int, 'waste_tonnes_per_day', null, 151::numeric, 'MT/day', 'p26-t37'),
      ('T', 2023, null::int, 'waste_tonnes_per_day', null, 157::numeric, 'MT/day', 'p26-t37'),
      ('T', 2024, null::int, 'waste_tonnes_per_day', null, 161::numeric, 'MT/day', 'p26-t37'),
      ('T', 2025, null::int, 'waste_tonnes_per_day', null, 167::numeric, 'MT/day', 'p26-t37'),
      (null, 2021, null::int, 'waste_tonnes_per_day', null, 5996::numeric, 'MT/day', 'p26-t37'),
      (null, 2022, null::int, 'waste_tonnes_per_day', null, 6385::numeric, 'MT/day', 'p26-t37'),
      (null, 2023, null::int, 'waste_tonnes_per_day', null, 6595::numeric, 'MT/day', 'p26-t37'),
      (null, 2023, null::int, 'waste_tonnes_per_day_other_facilities', null, 2019::numeric, 'MT/day', 'p26-t37'),
      (null, 2024, null::int, 'waste_tonnes_per_day', null, 6656::numeric, 'MT/day', 'p26-t37'),
      (null, 2024, null::int, 'waste_tonnes_per_day_other_facilities', null, 2033::numeric, 'MT/day', 'p26-t37'),
      (null, 2025, null::int, 'waste_tonnes_per_day', null, 6955::numeric, 'MT/day', 'p26-t37'),
      (null, 2025, null::int, 'waste_tonnes_per_day_other_facilities', null, 2067::numeric, 'MT/day', 'p26-t37'),
      ('A', 2011, null::int, 'slum_population_pct', null, 34::numeric, '%', 'p26-t11'),
      ('A', 2025, null::int, 'waste_total', null, 45625::numeric, 'MT', 'p26-t11'),
      ('A', 2025, null::int, 'waste_per_capita', null, 0.64::numeric, 'kg/person/day', 'p26-t11'),
      ('B', 2011, null::int, 'slum_population_pct', null, 11::numeric, '%', 'p26-t11'),
      ('B', 2025, null::int, 'waste_total', null, 26645::numeric, 'MT', 'p26-t11'),
      ('B', 2025, null::int, 'waste_per_capita', null, 0.54::numeric, 'kg/person/day', 'p26-t11'),
      ('C', 2011, null::int, 'slum_population_pct', null, 0::numeric, '%', 'p26-t11'),
      ('C', 2025, null::int, 'waste_total', null, 42340::numeric, 'MT', 'p26-t11'),
      ('C', 2025, null::int, 'waste_per_capita', null, 0.66::numeric, 'kg/person/day', 'p26-t11'),
      ('D', 2011, null::int, 'slum_population_pct', null, 10::numeric, '%', 'p26-t11'),
      ('D', 2025, null::int, 'waste_total', null, 37960::numeric, 'MT', 'p26-t11'),
      ('D', 2025, null::int, 'waste_per_capita', null, 0.28::numeric, 'kg/person/day', 'p26-t11'),
      ('E', 2011, null::int, 'slum_population_pct', null, 20::numeric, '%', 'p26-t11'),
      ('E', 2025, null::int, 'waste_total', null, 48180::numeric, 'MT', 'p26-t11'),
      ('E', 2025, null::int, 'waste_per_capita', null, 0.32::numeric, 'kg/person/day', 'p26-t11'),
      ('F/N', 2011, null::int, 'slum_population_pct', null, 58::numeric, '%', 'p26-t11'),
      ('F/N', 2025, null::int, 'waste_total', null, 60955::numeric, 'MT', 'p26-t11'),
      ('F/N', 2025, null::int, 'waste_per_capita', null, 0.3::numeric, 'kg/person/day', 'p26-t11'),
      ('F/S', 2011, null::int, 'slum_population_pct', null, 26::numeric, '%', 'p26-t11'),
      ('F/S', 2025, null::int, 'waste_total', null, 42340::numeric, 'MT', 'p26-t11'),
      ('F/S', 2025, null::int, 'waste_per_capita', null, 0.31::numeric, 'kg/person/day', 'p26-t11'),
      ('G/N', 2011, null::int, 'slum_population_pct', null, 32::numeric, '%', 'p26-t11'),
      ('G/N', 2025, null::int, 'waste_total', null, 97090::numeric, 'MT', 'p26-t11'),
      ('G/N', 2025, null::int, 'waste_per_capita', null, 0.42::numeric, 'kg/person/day', 'p26-t11'),
      ('G/S', 2011, null::int, 'slum_population_pct', null, 21::numeric, '%', 'p26-t11'),
      ('G/S', 2025, null::int, 'waste_total', null, 39055::numeric, 'MT', 'p26-t11'),
      ('G/S', 2025, null::int, 'waste_per_capita', null, 0.27::numeric, 'kg/person/day', 'p26-t11'),
      ('H/E', 2011, null::int, 'slum_population_pct', null, 42::numeric, '%', 'p26-t11'),
      ('H/E', 2025, null::int, 'waste_total', null, 63510::numeric, 'MT', 'p26-t11'),
      ('H/E', 2025, null::int, 'waste_per_capita', null, 0.3::numeric, 'kg/person/day', 'p26-t11'),
      ('H/W', 2011, null::int, 'slum_population_pct', null, 39::numeric, '%', 'p26-t11'),
      ('H/W', 2025, null::int, 'waste_total', null, 70810::numeric, 'MT', 'p26-t11'),
      ('H/W', 2025, null::int, 'waste_per_capita', null, 0.6::numeric, 'kg/person/day', 'p26-t11'),
      ('K/E', 2011, null::int, 'slum_population_pct', null, 49::numeric, '%', 'p26-t11'),
      ('K/E', 2025, null::int, 'waste_total', null, 116070::numeric, 'MT', 'p26-t11'),
      ('K/E', 2025, null::int, 'waste_per_capita', null, 0.37::numeric, 'kg/person/day', 'p26-t11'),
      ('K/W', 2011, null::int, 'slum_population_pct', null, 15::numeric, '%', 'p26-t11'),
      ('K/W', 2025, null::int, 'waste_total', null, 113515::numeric, 'MT', 'p26-t11'),
      ('K/W', 2025, null::int, 'waste_per_capita', null, 0.39::numeric, 'kg/person/day', 'p26-t11'),
      ('P/N', 2011, null::int, 'slum_population_pct', null, 54::numeric, '%', 'p26-t11'),
      ('P/N', 2025, null::int, 'waste_total', null, 110960::numeric, 'MT', 'p26-t11'),
      ('P/N', 2025, null::int, 'waste_per_capita', null, 0.31::numeric, 'kg/person/day', 'p26-t11'),
      ('P/S', 2011, null::int, 'slum_population_pct', null, 57::numeric, '%', 'p26-t11'),
      ('P/S', 2025, null::int, 'waste_total', null, 69715::numeric, 'MT', 'p26-t11'),
      ('P/S', 2025, null::int, 'waste_per_capita', null, 0.39::numeric, 'kg/person/day', 'p26-t11'),
      ('R/C', 2011, null::int, 'slum_population_pct', null, 19::numeric, '%', 'p26-t11'),
      ('R/C', 2025, null::int, 'waste_total', null, 62050::numeric, 'MT', 'p26-t11'),
      ('R/C', 2025, null::int, 'waste_per_capita', null, 0.29::numeric, 'kg/person/day', 'p26-t11'),
      ('R/N', 2011, null::int, 'slum_population_pct', null, 51::numeric, '%', 'p26-t11'),
      ('R/N', 2025, null::int, 'waste_total', null, 43070::numeric, 'MT', 'p26-t11'),
      ('R/N', 2025, null::int, 'waste_per_capita', null, 0.26::numeric, 'kg/person/day', 'p26-t11'),
      ('R/S', 2011, null::int, 'slum_population_pct', null, 58::numeric, '%', 'p26-t11'),
      ('R/S', 2025, null::int, 'waste_total', null, 59130::numeric, 'MT', 'p26-t11'),
      ('R/S', 2025, null::int, 'waste_per_capita', null, 0.22::numeric, 'kg/person/day', 'p26-t11'),
      ('L', 2011, null::int, 'slum_population_pct', null, 54::numeric, '%', 'p26-t11'),
      ('L', 2025, null::int, 'waste_total', null, 134320::numeric, 'MT', 'p26-t11'),
      ('L', 2025, null::int, 'waste_per_capita', null, 0.39::numeric, 'kg/person/day', 'p26-t11'),
      ('M/E', 2011, null::int, 'slum_population_pct', null, 30::numeric, '%', 'p26-t11'),
      ('M/E', 2025, null::int, 'waste_total', null, 145270::numeric, 'MT', 'p26-t11'),
      ('M/E', 2025, null::int, 'waste_per_capita', null, 0.47::numeric, 'kg/person/day', 'p26-t11'),
      ('M/W', 2011, null::int, 'slum_population_pct', null, 53::numeric, '%', 'p26-t11'),
      ('M/W', 2025, null::int, 'waste_total', null, 85775::numeric, 'MT', 'p26-t11'),
      ('M/W', 2025, null::int, 'waste_per_capita', null, 0.54::numeric, 'kg/person/day', 'p26-t11'),
      ('N', 2011, null::int, 'slum_population_pct', null, 62::numeric, '%', 'p26-t11'),
      ('N', 2025, null::int, 'waste_total', null, 70080::numeric, 'MT', 'p26-t11'),
      ('N', 2025, null::int, 'waste_per_capita', null, 0.29::numeric, 'kg/person/day', 'p26-t11'),
      ('S', 2011, null::int, 'slum_population_pct', null, 72::numeric, '%', 'p26-t11'),
      ('S', 2025, null::int, 'waste_total', null, 101105::numeric, 'MT', 'p26-t11'),
      ('S', 2025, null::int, 'waste_per_capita', null, 0.35::numeric, 'kg/person/day', 'p26-t11'),
      ('T', 2011, null::int, 'slum_population_pct', null, 33::numeric, '%', 'p26-t11'),
      ('T', 2025, null::int, 'waste_total', null, 60955::numeric, 'MT', 'p26-t11'),
      ('T', 2025, null::int, 'waste_per_capita', null, 0.46::numeric, 'kg/person/day', 'p26-t11'),
      (null, 2016, 1, 'aqi_monthly_avg', null, 170::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 1, 'aqi_monthly_avg', null, 186::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 1, 'aqi_monthly_avg', null, 176::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 1, 'aqi_monthly_avg', null, 171::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 1, 'aqi_monthly_avg', null, 151::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 1, 'aqi_monthly_avg', null, 187::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 1, 'aqi_monthly_avg', null, 173::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 1, 'aqi_monthly_avg', null, 186::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 1, 'aqi_monthly_avg', null, 113::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 1, 'aqi_monthly_avg', null, 137::numeric, 'AQI', 'p26-t29'),
      (null, 2016, 2, 'aqi_monthly_avg', null, 98::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 2, 'aqi_monthly_avg', null, 168::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 2, 'aqi_monthly_avg', null, 147::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 2, 'aqi_monthly_avg', null, 150::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 2, 'aqi_monthly_avg', null, 160::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 2, 'aqi_monthly_avg', null, 154::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 2, 'aqi_monthly_avg', null, 160::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 2, 'aqi_monthly_avg', null, 180::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 2, 'aqi_monthly_avg', null, 117::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 2, 'aqi_monthly_avg', null, 130::numeric, 'AQI', 'p26-t29'),
      (null, 2016, 3, 'aqi_monthly_avg', null, 103::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 3, 'aqi_monthly_avg', null, 126::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 3, 'aqi_monthly_avg', null, 127::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 3, 'aqi_monthly_avg', null, 119::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 3, 'aqi_monthly_avg', null, 107::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 3, 'aqi_monthly_avg', null, 161::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 3, 'aqi_monthly_avg', null, 160::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 3, 'aqi_monthly_avg', null, 140::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 3, 'aqi_monthly_avg', null, 98::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 3, 'aqi_monthly_avg', null, 108::numeric, 'AQI', 'p26-t29'),
      (null, 2016, 4, 'aqi_monthly_avg', null, 74::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 4, 'aqi_monthly_avg', null, 97::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 4, 'aqi_monthly_avg', null, 88::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 4, 'aqi_monthly_avg', null, 90::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 4, 'aqi_monthly_avg', null, 64::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 4, 'aqi_monthly_avg', null, 103::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 4, 'aqi_monthly_avg', null, 115::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 4, 'aqi_monthly_avg', null, 99::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 4, 'aqi_monthly_avg', null, 98::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 4, 'aqi_monthly_avg', null, 78::numeric, 'AQI', 'p26-t29'),
      (null, 2016, 5, 'aqi_monthly_avg', null, 70::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 5, 'aqi_monthly_avg', null, 66::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 5, 'aqi_monthly_avg', null, 80::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 5, 'aqi_monthly_avg', null, 85::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 5, 'aqi_monthly_avg', null, 55::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 5, 'aqi_monthly_avg', null, 78::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 5, 'aqi_monthly_avg', null, 128::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 5, 'aqi_monthly_avg', null, 70::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 5, 'aqi_monthly_avg', null, 78::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 5, 'aqi_monthly_avg', null, 69::numeric, 'AQI', 'p26-t29'),
      (null, 2016, 6, 'aqi_monthly_avg', null, 59::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 6, 'aqi_monthly_avg', null, 55::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 6, 'aqi_monthly_avg', null, 72::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 6, 'aqi_monthly_avg', null, 68::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 6, 'aqi_monthly_avg', null, 34::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 6, 'aqi_monthly_avg', null, 59::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 6, 'aqi_monthly_avg', null, 51::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 6, 'aqi_monthly_avg', null, 65::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 6, 'aqi_monthly_avg', null, 52::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 6, 'aqi_monthly_avg', null, 56::numeric, 'AQI', 'p26-t29'),
      (null, 2016, 7, 'aqi_monthly_avg', null, 68::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 7, 'aqi_monthly_avg', null, 78::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 7, 'aqi_monthly_avg', null, 65::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 7, 'aqi_monthly_avg', null, 53::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 7, 'aqi_monthly_avg', null, 30::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 7, 'aqi_monthly_avg', null, 54::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 7, 'aqi_monthly_avg', null, 58::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 7, 'aqi_monthly_avg', null, 66::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 7, 'aqi_monthly_avg', null, 43::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 7, 'aqi_monthly_avg', null, 51::numeric, 'AQI', 'p26-t29'),
      (null, 2016, 8, 'aqi_monthly_avg', null, 56::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 8, 'aqi_monthly_avg', null, 51::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 8, 'aqi_monthly_avg', null, 69::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 8, 'aqi_monthly_avg', null, 56::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 8, 'aqi_monthly_avg', null, 33::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 8, 'aqi_monthly_avg', null, 51::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 8, 'aqi_monthly_avg', null, 63::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 8, 'aqi_monthly_avg', null, 51::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 8, 'aqi_monthly_avg', null, 41::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 8, 'aqi_monthly_avg', null, 46::numeric, 'AQI', 'p26-t29'),
      (null, 2016, 9, 'aqi_monthly_avg', null, 55::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 9, 'aqi_monthly_avg', null, 71::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 9, 'aqi_monthly_avg', null, 81::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 9, 'aqi_monthly_avg', null, 45::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 9, 'aqi_monthly_avg', null, 60::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 9, 'aqi_monthly_avg', null, 50::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 9, 'aqi_monthly_avg', null, 46::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 9, 'aqi_monthly_avg', null, 54::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 9, 'aqi_monthly_avg', null, 45::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 9, 'aqi_monthly_avg', null, 48::numeric, 'AQI', 'p26-t29'),
      (null, 2016, 10, 'aqi_monthly_avg', null, 91::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 10, 'aqi_monthly_avg', null, 107::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 10, 'aqi_monthly_avg', null, 115::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 10, 'aqi_monthly_avg', null, 85::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 10, 'aqi_monthly_avg', null, 94::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 10, 'aqi_monthly_avg', null, 95::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 10, 'aqi_monthly_avg', null, 91::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 10, 'aqi_monthly_avg', null, 144::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 10, 'aqi_monthly_avg', null, 77::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 10, 'aqi_monthly_avg', null, 94::numeric, 'AQI', 'p26-t29'),
      (null, 2016, 11, 'aqi_monthly_avg', null, 113::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 11, 'aqi_monthly_avg', null, 136::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 11, 'aqi_monthly_avg', null, 137::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 11, 'aqi_monthly_avg', null, 132::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 11, 'aqi_monthly_avg', null, 145::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 11, 'aqi_monthly_avg', null, 135::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 11, 'aqi_monthly_avg', null, 162::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 11, 'aqi_monthly_avg', null, 131::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 11, 'aqi_monthly_avg', null, 142::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 11, 'aqi_monthly_avg', null, 126::numeric, 'AQI', 'p26-t29'),
      (null, 2016, 12, 'aqi_monthly_avg', null, 164::numeric, 'AQI', 'p26-t29'),
      (null, 2017, 12, 'aqi_monthly_avg', null, 152::numeric, 'AQI', 'p26-t29'),
      (null, 2018, 12, 'aqi_monthly_avg', null, 151::numeric, 'AQI', 'p26-t29'),
      (null, 2019, 12, 'aqi_monthly_avg', null, 179::numeric, 'AQI', 'p26-t29'),
      (null, 2020, 12, 'aqi_monthly_avg', null, 160::numeric, 'AQI', 'p26-t29'),
      (null, 2021, 12, 'aqi_monthly_avg', null, 158::numeric, 'AQI', 'p26-t29'),
      (null, 2022, 12, 'aqi_monthly_avg', null, 191::numeric, 'AQI', 'p26-t29'),
      (null, 2023, 12, 'aqi_monthly_avg', null, 141::numeric, 'AQI', 'p26-t29'),
      (null, 2024, 12, 'aqi_monthly_avg', null, 144::numeric, 'AQI', 'p26-t29'),
      (null, 2025, 12, 'aqi_monthly_avg', null, 122::numeric, 'AQI', 'p26-t29'),
      ('A', 2025, null::int, 'air_quality_days', 'Good', 81::numeric, 'days', 'p26-t30'),
      ('A', 2025, null::int, 'air_quality_days', 'Satisfactory', 151::numeric, 'days', 'p26-t30'),
      ('A', 2025, null::int, 'air_quality_days', 'Moderate', 94::numeric, 'days', 'p26-t30'),
      ('A', 2025, null::int, 'air_quality_days', 'Poor', 6::numeric, 'days', 'p26-t30'),
      ('A', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('A', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('A', 2025, null::int, 'air_quality_days', 'No data', 34::numeric, 'days', 'p26-t30'),
      ('E', 2025, null::int, 'air_quality_days', 'Good', 132::numeric, 'days', 'p26-t30'),
      ('E', 2025, null::int, 'air_quality_days', 'Satisfactory', 109::numeric, 'days', 'p26-t30'),
      ('E', 2025, null::int, 'air_quality_days', 'Moderate', 113::numeric, 'days', 'p26-t30'),
      ('E', 2025, null::int, 'air_quality_days', 'Poor', 2::numeric, 'days', 'p26-t30'),
      ('E', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('E', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('E', 2025, null::int, 'air_quality_days', 'No data', 9::numeric, 'days', 'p26-t30'),
      ('F/S', 2025, null::int, 'air_quality_days', 'Good', 151::numeric, 'days', 'p26-t30'),
      ('F/S', 2025, null::int, 'air_quality_days', 'Satisfactory', 125::numeric, 'days', 'p26-t30'),
      ('F/S', 2025, null::int, 'air_quality_days', 'Moderate', 69::numeric, 'days', 'p26-t30'),
      ('F/S', 2025, null::int, 'air_quality_days', 'Poor', 0::numeric, 'days', 'p26-t30'),
      ('F/S', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('F/S', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('F/S', 2025, null::int, 'air_quality_days', 'No data', 20::numeric, 'days', 'p26-t30'),
      ('F/N', 2025, null::int, 'air_quality_days', 'Good', 73::numeric, 'days', 'p26-t30'),
      ('F/N', 2025, null::int, 'air_quality_days', 'Satisfactory', 120::numeric, 'days', 'p26-t30'),
      ('F/N', 2025, null::int, 'air_quality_days', 'Moderate', 93::numeric, 'days', 'p26-t30'),
      ('F/N', 2025, null::int, 'air_quality_days', 'Poor', 5::numeric, 'days', 'p26-t30'),
      ('F/N', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('F/N', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('F/N', 2025, null::int, 'air_quality_days', 'No data', 74::numeric, 'days', 'p26-t30'),
      ('G/S', 2025, null::int, 'air_quality_days', 'Good', 60::numeric, 'days', 'p26-t30'),
      ('G/S', 2025, null::int, 'air_quality_days', 'Satisfactory', 162::numeric, 'days', 'p26-t30'),
      ('G/S', 2025, null::int, 'air_quality_days', 'Moderate', 115::numeric, 'days', 'p26-t30'),
      ('G/S', 2025, null::int, 'air_quality_days', 'Poor', 1::numeric, 'days', 'p26-t30'),
      ('G/S', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('G/S', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('G/S', 2025, null::int, 'air_quality_days', 'No data', 28::numeric, 'days', 'p26-t30'),
      ('H/E', 2025, null::int, 'air_quality_days', 'Good', 41::numeric, 'days', 'p26-t30'),
      ('H/E', 2025, null::int, 'air_quality_days', 'Satisfactory', 116::numeric, 'days', 'p26-t30'),
      ('H/E', 2025, null::int, 'air_quality_days', 'Moderate', 89::numeric, 'days', 'p26-t30'),
      ('H/E', 2025, null::int, 'air_quality_days', 'Poor', 9::numeric, 'days', 'p26-t30'),
      ('H/E', 2025, null::int, 'air_quality_days', 'Very Poor', 2::numeric, 'days', 'p26-t30'),
      ('H/E', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('H/E', 2025, null::int, 'air_quality_days', 'No data', 109::numeric, 'days', 'p26-t30'),
      ('H/W', 2025, null::int, 'air_quality_days', 'Good', 97::numeric, 'days', 'p26-t30'),
      ('H/W', 2025, null::int, 'air_quality_days', 'Satisfactory', 87::numeric, 'days', 'p26-t30'),
      ('H/W', 2025, null::int, 'air_quality_days', 'Moderate', 107::numeric, 'days', 'p26-t30'),
      ('H/W', 2025, null::int, 'air_quality_days', 'Poor', 5::numeric, 'days', 'p26-t30'),
      ('H/W', 2025, null::int, 'air_quality_days', 'Very Poor', 3::numeric, 'days', 'p26-t30'),
      ('H/W', 2025, null::int, 'air_quality_days', 'Severe', 1::numeric, 'days', 'p26-t30'),
      ('H/W', 2025, null::int, 'air_quality_days', 'No data', 65::numeric, 'days', 'p26-t30'),
      ('K/E', 2025, null::int, 'air_quality_days', 'Good', 60::numeric, 'days', 'p26-t30'),
      ('K/E', 2025, null::int, 'air_quality_days', 'Satisfactory', 128::numeric, 'days', 'p26-t30'),
      ('K/E', 2025, null::int, 'air_quality_days', 'Moderate', 92::numeric, 'days', 'p26-t30'),
      ('K/E', 2025, null::int, 'air_quality_days', 'Poor', 4::numeric, 'days', 'p26-t30'),
      ('K/E', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('K/E', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('K/E', 2025, null::int, 'air_quality_days', 'No data', 81::numeric, 'days', 'p26-t30'),
      ('P/N', 2025, null::int, 'air_quality_days', 'Good', 117::numeric, 'days', 'p26-t30'),
      ('P/N', 2025, null::int, 'air_quality_days', 'Satisfactory', 113::numeric, 'days', 'p26-t30'),
      ('P/N', 2025, null::int, 'air_quality_days', 'Moderate', 120::numeric, 'days', 'p26-t30'),
      ('P/N', 2025, null::int, 'air_quality_days', 'Poor', 14::numeric, 'days', 'p26-t30'),
      ('P/N', 2025, null::int, 'air_quality_days', 'Very Poor', 1::numeric, 'days', 'p26-t30'),
      ('P/N', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('P/N', 2025, null::int, 'air_quality_days', 'No data', 1::numeric, 'days', 'p26-t30'),
      ('R/C', 2025, null::int, 'air_quality_days', 'Good', 91::numeric, 'days', 'p26-t30'),
      ('R/C', 2025, null::int, 'air_quality_days', 'Satisfactory', 136::numeric, 'days', 'p26-t30'),
      ('R/C', 2025, null::int, 'air_quality_days', 'Moderate', 86::numeric, 'days', 'p26-t30'),
      ('R/C', 2025, null::int, 'air_quality_days', 'Poor', 6::numeric, 'days', 'p26-t30'),
      ('R/C', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('R/C', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('R/C', 2025, null::int, 'air_quality_days', 'No data', 46::numeric, 'days', 'p26-t30'),
      ('R/S', 2025, null::int, 'air_quality_days', 'Good', 126::numeric, 'days', 'p26-t30'),
      ('R/S', 2025, null::int, 'air_quality_days', 'Satisfactory', 78::numeric, 'days', 'p26-t30'),
      ('R/S', 2025, null::int, 'air_quality_days', 'Moderate', 95::numeric, 'days', 'p26-t30'),
      ('R/S', 2025, null::int, 'air_quality_days', 'Poor', 1::numeric, 'days', 'p26-t30'),
      ('R/S', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('R/S', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('R/S', 2025, null::int, 'air_quality_days', 'No data', 66::numeric, 'days', 'p26-t30'),
      ('L', 2025, null::int, 'air_quality_days', 'Good', 53::numeric, 'days', 'p26-t30'),
      ('L', 2025, null::int, 'air_quality_days', 'Satisfactory', 143::numeric, 'days', 'p26-t30'),
      ('L', 2025, null::int, 'air_quality_days', 'Moderate', 136::numeric, 'days', 'p26-t30'),
      ('L', 2025, null::int, 'air_quality_days', 'Poor', 1::numeric, 'days', 'p26-t30'),
      ('L', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('L', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('L', 2025, null::int, 'air_quality_days', 'No data', 33::numeric, 'days', 'p26-t30'),
      ('M/E', 2025, null::int, 'air_quality_days', 'Good', 37::numeric, 'days', 'p26-t30'),
      ('M/E', 2025, null::int, 'air_quality_days', 'Satisfactory', 116::numeric, 'days', 'p26-t30'),
      ('M/E', 2025, null::int, 'air_quality_days', 'Moderate', 132::numeric, 'days', 'p26-t30'),
      ('M/E', 2025, null::int, 'air_quality_days', 'Poor', 36::numeric, 'days', 'p26-t30'),
      ('M/E', 2025, null::int, 'air_quality_days', 'Very Poor', 5::numeric, 'days', 'p26-t30'),
      ('M/E', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('M/E', 2025, null::int, 'air_quality_days', 'No data', 41::numeric, 'days', 'p26-t30'),
      ('M/W', 2025, null::int, 'air_quality_days', 'Good', 118::numeric, 'days', 'p26-t30'),
      ('M/W', 2025, null::int, 'air_quality_days', 'Satisfactory', 108::numeric, 'days', 'p26-t30'),
      ('M/W', 2025, null::int, 'air_quality_days', 'Moderate', 138::numeric, 'days', 'p26-t30'),
      ('M/W', 2025, null::int, 'air_quality_days', 'Poor', 0::numeric, 'days', 'p26-t30'),
      ('M/W', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('M/W', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('M/W', 2025, null::int, 'air_quality_days', 'No data', 1::numeric, 'days', 'p26-t30'),
      ('N', 2025, null::int, 'air_quality_days', 'Good', 134::numeric, 'days', 'p26-t30'),
      ('N', 2025, null::int, 'air_quality_days', 'Satisfactory', 76::numeric, 'days', 'p26-t30'),
      ('N', 2025, null::int, 'air_quality_days', 'Moderate', 135::numeric, 'days', 'p26-t30'),
      ('N', 2025, null::int, 'air_quality_days', 'Poor', 9::numeric, 'days', 'p26-t30'),
      ('N', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('N', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('N', 2025, null::int, 'air_quality_days', 'No data', 11::numeric, 'days', 'p26-t30'),
      ('S', 2025, null::int, 'air_quality_days', 'Good', 163::numeric, 'days', 'p26-t30'),
      ('S', 2025, null::int, 'air_quality_days', 'Satisfactory', 77::numeric, 'days', 'p26-t30'),
      ('S', 2025, null::int, 'air_quality_days', 'Moderate', 109::numeric, 'days', 'p26-t30'),
      ('S', 2025, null::int, 'air_quality_days', 'Poor', 0::numeric, 'days', 'p26-t30'),
      ('S', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('S', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('S', 2025, null::int, 'air_quality_days', 'No data', 16::numeric, 'days', 'p26-t30'),
      ('T', 2025, null::int, 'air_quality_days', 'Good', 77::numeric, 'days', 'p26-t30'),
      ('T', 2025, null::int, 'air_quality_days', 'Satisfactory', 132::numeric, 'days', 'p26-t30'),
      ('T', 2025, null::int, 'air_quality_days', 'Moderate', 112::numeric, 'days', 'p26-t30'),
      ('T', 2025, null::int, 'air_quality_days', 'Poor', 3::numeric, 'days', 'p26-t30'),
      ('T', 2025, null::int, 'air_quality_days', 'Very Poor', 0::numeric, 'days', 'p26-t30'),
      ('T', 2025, null::int, 'air_quality_days', 'Severe', 0::numeric, 'days', 'p26-t30'),
      ('T', 2025, null::int, 'air_quality_days', 'No data', 41::numeric, 'days', 'p26-t30'),
      ('A', 2024, null::int, 'complaints_closed', null, 1306::numeric, 'complaints', 'p25-t45'),
      ('A', 2024, null::int, 'avg_days_to_close', null, 64::numeric, 'days', 'p25-t45'),
      ('B', 2024, null::int, 'complaints_closed', null, 966::numeric, 'complaints', 'p25-t45'),
      ('B', 2024, null::int, 'avg_days_to_close', null, 79::numeric, 'days', 'p25-t45'),
      ('C', 2024, null::int, 'complaints_closed', null, 3257::numeric, 'complaints', 'p25-t45'),
      ('C', 2024, null::int, 'avg_days_to_close', null, 32::numeric, 'days', 'p25-t45'),
      ('D', 2024, null::int, 'complaints_closed', null, 3545::numeric, 'complaints', 'p25-t45'),
      ('D', 2024, null::int, 'avg_days_to_close', null, 20::numeric, 'days', 'p25-t45'),
      ('E', 2024, null::int, 'complaints_closed', null, 3570::numeric, 'complaints', 'p25-t45'),
      ('E', 2024, null::int, 'avg_days_to_close', null, 81::numeric, 'days', 'p25-t45'),
      ('F/N', 2024, null::int, 'complaints_closed', null, 3693::numeric, 'complaints', 'p25-t45'),
      ('F/N', 2024, null::int, 'avg_days_to_close', null, 43::numeric, 'days', 'p25-t45'),
      ('F/S', 2024, null::int, 'complaints_closed', null, 2590::numeric, 'complaints', 'p25-t45'),
      ('F/S', 2024, null::int, 'avg_days_to_close', null, 37::numeric, 'days', 'p25-t45'),
      ('G/N', 2024, null::int, 'complaints_closed', null, 3921::numeric, 'complaints', 'p25-t45'),
      ('G/N', 2024, null::int, 'avg_days_to_close', null, 52::numeric, 'days', 'p25-t45'),
      ('G/S', 2024, null::int, 'complaints_closed', null, 3064::numeric, 'complaints', 'p25-t45'),
      ('G/S', 2024, null::int, 'avg_days_to_close', null, 37::numeric, 'days', 'p25-t45'),
      ('H/E', 2024, null::int, 'complaints_closed', null, 3782::numeric, 'complaints', 'p25-t45'),
      ('H/E', 2024, null::int, 'avg_days_to_close', null, 40::numeric, 'days', 'p25-t45'),
      ('H/W', 2024, null::int, 'complaints_closed', null, 4096::numeric, 'complaints', 'p25-t45'),
      ('H/W', 2024, null::int, 'avg_days_to_close', null, 48::numeric, 'days', 'p25-t45'),
      ('K/E', 2024, null::int, 'complaints_closed', null, 6826::numeric, 'complaints', 'p25-t45'),
      ('K/E', 2024, null::int, 'avg_days_to_close', null, 59::numeric, 'days', 'p25-t45'),
      ('K/W', 2024, null::int, 'complaints_closed', null, 6286::numeric, 'complaints', 'p25-t45'),
      ('K/W', 2024, null::int, 'avg_days_to_close', null, 64::numeric, 'days', 'p25-t45'),
      ('L', 2024, null::int, 'complaints_closed', null, 4912::numeric, 'complaints', 'p25-t45'),
      ('L', 2024, null::int, 'avg_days_to_close', null, 20::numeric, 'days', 'p25-t45'),
      ('M/E', 2024, null::int, 'complaints_closed', null, 3530::numeric, 'complaints', 'p25-t45'),
      ('M/E', 2024, null::int, 'avg_days_to_close', null, 28::numeric, 'days', 'p25-t45'),
      ('M/W', 2024, null::int, 'complaints_closed', null, 3587::numeric, 'complaints', 'p25-t45'),
      ('M/W', 2024, null::int, 'avg_days_to_close', null, 28::numeric, 'days', 'p25-t45'),
      ('N', 2024, null::int, 'complaints_closed', null, 4967::numeric, 'complaints', 'p25-t45'),
      ('N', 2024, null::int, 'avg_days_to_close', null, 33::numeric, 'days', 'p25-t45'),
      ('P/N', 2024, null::int, 'complaints_closed', null, 3316::numeric, 'complaints', 'p25-t45'),
      ('P/N', 2024, null::int, 'avg_days_to_close', null, 68::numeric, 'days', 'p25-t45'),
      ('P/S', 2024, null::int, 'complaints_closed', null, 3114::numeric, 'complaints', 'p25-t45'),
      ('P/S', 2024, null::int, 'avg_days_to_close', null, 35::numeric, 'days', 'p25-t45'),
      ('R/C', 2024, null::int, 'complaints_closed', null, 5033::numeric, 'complaints', 'p25-t45'),
      ('R/C', 2024, null::int, 'avg_days_to_close', null, 23::numeric, 'days', 'p25-t45'),
      ('R/N', 2024, null::int, 'complaints_closed', null, 3121::numeric, 'complaints', 'p25-t45'),
      ('R/N', 2024, null::int, 'avg_days_to_close', null, 15::numeric, 'days', 'p25-t45'),
      ('R/S', 2024, null::int, 'complaints_closed', null, 4565::numeric, 'complaints', 'p25-t45'),
      ('R/S', 2024, null::int, 'avg_days_to_close', null, 14::numeric, 'days', 'p25-t45'),
      ('S', 2024, null::int, 'complaints_closed', null, 2671::numeric, 'complaints', 'p25-t45'),
      ('S', 2024, null::int, 'avg_days_to_close', null, 50::numeric, 'days', 'p25-t45'),
      ('T', 2024, null::int, 'complaints_closed', null, 2590::numeric, 'complaints', 'p25-t45'),
      ('T', 2024, null::int, 'avg_days_to_close', null, 39::numeric, 'days', 'p25-t45'),
      (null, 2024, null::int, 'avg_days_to_close', null, 41::numeric, 'days', 'p25-t45'),
      (null, 2024, null::int, 'complaints_closed', null, 88308::numeric, 'complaints', 'p25-t45'),
      ('A', 2024, null::int, 'water_supply_zones', null, 13::numeric, 'zones', 'p25-t4'),
      ('A', 2024, null::int, 'water_supply_hours', null, 2.46::numeric, 'hours/day', 'p25-t4'),
      ('A', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 10::numeric, 'zones', 'p25-t4'),
      ('A', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('A', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('A', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('A', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('A', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('A', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('A', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('B', 2024, null::int, 'water_supply_zones', null, 6::numeric, 'zones', 'p25-t4'),
      ('B', 2024, null::int, 'water_supply_hours', null, 1.88::numeric, 'hours/day', 'p25-t4'),
      ('B', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 5::numeric, 'zones', 'p25-t4'),
      ('B', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('B', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('B', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('B', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('B', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('B', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('B', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('C', 2024, null::int, 'water_supply_zones', null, 5::numeric, 'zones', 'p25-t4'),
      ('C', 2024, null::int, 'water_supply_hours', null, 1.53::numeric, 'hours/day', 'p25-t4'),
      ('C', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 5::numeric, 'zones', 'p25-t4'),
      ('C', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('C', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('C', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('C', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('C', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('C', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('C', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('D', 2024, null::int, 'water_supply_zones', null, 20::numeric, 'zones', 'p25-t4'),
      ('D', 2024, null::int, 'water_supply_hours', null, 3.5::numeric, 'hours/day', 'p25-t4'),
      ('D', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 7::numeric, 'zones', 'p25-t4'),
      ('D', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 6::numeric, 'zones', 'p25-t4'),
      ('D', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 5::numeric, 'zones', 'p25-t4'),
      ('D', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('D', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('D', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('D', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('D', 2024, null::int, 'water_zones_by_hours', 'Not available', 1::numeric, 'zones', 'p25-t4'),
      ('E', 2024, null::int, 'water_supply_zones', null, 16::numeric, 'zones', 'p25-t4'),
      ('E', 2024, null::int, 'water_supply_hours', null, 4.87::numeric, 'hours/day', 'p25-t4'),
      ('E', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 10::numeric, 'zones', 'p25-t4'),
      ('E', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 3::numeric, 'zones', 'p25-t4'),
      ('E', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('E', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('E', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('E', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('E', 2024, null::int, 'water_zones_by_hours', '24 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('E', 2024, null::int, 'water_zones_by_hours', 'Not available', 1::numeric, 'zones', 'p25-t4'),
      ('F/N', 2024, null::int, 'water_supply_zones', null, 9::numeric, 'zones', 'p25-t4'),
      ('F/N', 2024, null::int, 'water_supply_hours', null, 3.3::numeric, 'hours/day', 'p25-t4'),
      ('F/N', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 3::numeric, 'zones', 'p25-t4'),
      ('F/N', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 4::numeric, 'zones', 'p25-t4'),
      ('F/N', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('F/N', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('F/N', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('F/N', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('F/N', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('F/N', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('F/S', 2024, null::int, 'water_supply_zones', null, 10::numeric, 'zones', 'p25-t4'),
      ('F/S', 2024, null::int, 'water_supply_hours', null, 5.03::numeric, 'hours/day', 'p25-t4'),
      ('F/S', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('F/S', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 8::numeric, 'zones', 'p25-t4'),
      ('F/S', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('F/S', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('F/S', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('F/S', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('F/S', 2024, null::int, 'water_zones_by_hours', '24 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('F/S', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('G/N', 2024, null::int, 'water_supply_zones', null, 4::numeric, 'zones', 'p25-t4'),
      ('G/N', 2024, null::int, 'water_supply_hours', null, 4.25::numeric, 'hours/day', 'p25-t4'),
      ('G/N', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('G/N', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('G/N', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('G/N', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('G/N', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('G/N', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('G/N', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('G/N', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('G/S', 2024, null::int, 'water_supply_zones', null, 9::numeric, 'zones', 'p25-t4'),
      ('G/S', 2024, null::int, 'water_supply_hours', null, 5.53::numeric, 'hours/day', 'p25-t4'),
      ('G/S', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('G/S', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 5::numeric, 'zones', 'p25-t4'),
      ('G/S', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('G/S', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('G/S', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('G/S', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('G/S', 2024, null::int, 'water_zones_by_hours', '24 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('G/S', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('H/E', 2024, null::int, 'water_supply_zones', null, 9::numeric, 'zones', 'p25-t4'),
      ('H/E', 2024, null::int, 'water_supply_hours', null, 3.11::numeric, 'hours/day', 'p25-t4'),
      ('H/E', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/E', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 9::numeric, 'zones', 'p25-t4'),
      ('H/E', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/E', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/E', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/E', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/E', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/E', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('H/W', 2024, null::int, 'water_supply_zones', null, 14::numeric, 'zones', 'p25-t4'),
      ('H/W', 2024, null::int, 'water_supply_hours', null, 3.25::numeric, 'hours/day', 'p25-t4'),
      ('H/W', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/W', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 14::numeric, 'zones', 'p25-t4'),
      ('H/W', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/W', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/W', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/W', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/W', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('H/W', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('K/E', 2024, null::int, 'water_supply_zones', null, 18::numeric, 'zones', 'p25-t4'),
      ('K/E', 2024, null::int, 'water_supply_hours', null, 6.48::numeric, 'hours/day', 'p25-t4'),
      ('K/E', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('K/E', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 14::numeric, 'zones', 'p25-t4'),
      ('K/E', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('K/E', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('K/E', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('K/E', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('K/E', 2024, null::int, 'water_zones_by_hours', '24 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('K/E', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('K/W', 2024, null::int, 'water_supply_zones', null, 21::numeric, 'zones', 'p25-t4'),
      ('K/W', 2024, null::int, 'water_supply_hours', null, 2.37::numeric, 'hours/day', 'p25-t4'),
      ('K/W', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 10::numeric, 'zones', 'p25-t4'),
      ('K/W', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 9::numeric, 'zones', 'p25-t4'),
      ('K/W', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('K/W', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('K/W', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('K/W', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('K/W', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('K/W', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('L', 2024, null::int, 'water_supply_zones', null, 8::numeric, 'zones', 'p25-t4'),
      ('L', 2024, null::int, 'water_supply_hours', null, 10.56::numeric, 'hours/day', 'p25-t4'),
      ('L', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('L', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('L', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('L', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('L', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 3::numeric, 'zones', 'p25-t4'),
      ('L', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('L', 2024, null::int, 'water_zones_by_hours', '24 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('L', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('M/E', 2024, null::int, 'water_supply_zones', null, 21::numeric, 'zones', 'p25-t4'),
      ('M/E', 2024, null::int, 'water_supply_hours', null, 7.56::numeric, 'hours/day', 'p25-t4'),
      ('M/E', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('M/E', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 8::numeric, 'zones', 'p25-t4'),
      ('M/E', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 7::numeric, 'zones', 'p25-t4'),
      ('M/E', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('M/E', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('M/E', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('M/E', 2024, null::int, 'water_zones_by_hours', '24 hrs', 4::numeric, 'zones', 'p25-t4'),
      ('M/E', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('M/W', 2024, null::int, 'water_supply_zones', null, 5::numeric, 'zones', 'p25-t4'),
      ('M/W', 2024, null::int, 'water_supply_hours', null, 11::numeric, 'hours/day', 'p25-t4'),
      ('M/W', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('M/W', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('M/W', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('M/W', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('M/W', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('M/W', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('M/W', 2024, null::int, 'water_zones_by_hours', '24 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('M/W', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('N', 2024, null::int, 'water_supply_zones', null, 9::numeric, 'zones', 'p25-t4'),
      ('N', 2024, null::int, 'water_supply_hours', null, 11.83::numeric, 'hours/day', 'p25-t4'),
      ('N', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('N', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('N', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('N', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('N', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('N', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('N', 2024, null::int, 'water_zones_by_hours', '24 hrs', 3::numeric, 'zones', 'p25-t4'),
      ('N', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('P/N', 2024, null::int, 'water_supply_zones', null, 19::numeric, 'zones', 'p25-t4'),
      ('P/N', 2024, null::int, 'water_supply_hours', null, 3.89::numeric, 'hours/day', 'p25-t4'),
      ('P/N', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 4::numeric, 'zones', 'p25-t4'),
      ('P/N', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 10::numeric, 'zones', 'p25-t4'),
      ('P/N', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 4::numeric, 'zones', 'p25-t4'),
      ('P/N', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('P/N', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('P/N', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('P/N', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('P/N', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('P/S', 2024, null::int, 'water_supply_zones', null, 15::numeric, 'zones', 'p25-t4'),
      ('P/S', 2024, null::int, 'water_supply_hours', null, 2.73::numeric, 'hours/day', 'p25-t4'),
      ('P/S', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('P/S', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 11::numeric, 'zones', 'p25-t4'),
      ('P/S', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('P/S', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('P/S', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('P/S', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('P/S', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('P/S', 2024, null::int, 'water_zones_by_hours', 'Not available', 2::numeric, 'zones', 'p25-t4'),
      ('R/C', 2024, null::int, 'water_supply_zones', null, 9::numeric, 'zones', 'p25-t4'),
      ('R/C', 2024, null::int, 'water_supply_hours', null, 3.54::numeric, 'hours/day', 'p25-t4'),
      ('R/C', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 4::numeric, 'zones', 'p25-t4'),
      ('R/C', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 4::numeric, 'zones', 'p25-t4'),
      ('R/C', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('R/C', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('R/C', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('R/C', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('R/C', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('R/C', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('R/N', 2024, null::int, 'water_supply_zones', null, 6::numeric, 'zones', 'p25-t4'),
      ('R/N', 2024, null::int, 'water_supply_hours', null, 2.46::numeric, 'hours/day', 'p25-t4'),
      ('R/N', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('R/N', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 4::numeric, 'zones', 'p25-t4'),
      ('R/N', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('R/N', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('R/N', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('R/N', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('R/N', 2024, null::int, 'water_zones_by_hours', '24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('R/N', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('R/S', 2024, null::int, 'water_supply_zones', null, 21::numeric, 'zones', 'p25-t4'),
      ('R/S', 2024, null::int, 'water_supply_hours', null, 4.48::numeric, 'hours/day', 'p25-t4'),
      ('R/S', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 6::numeric, 'zones', 'p25-t4'),
      ('R/S', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 10::numeric, 'zones', 'p25-t4'),
      ('R/S', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 3::numeric, 'zones', 'p25-t4'),
      ('R/S', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('R/S', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('R/S', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('R/S', 2024, null::int, 'water_zones_by_hours', '24 hrs', 1::numeric, 'zones', 'p25-t4'),
      ('R/S', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('S', 2024, null::int, 'water_supply_zones', null, 16::numeric, 'zones', 'p25-t4'),
      ('S', 2024, null::int, 'water_supply_hours', null, 12::numeric, 'hours/day', 'p25-t4'),
      ('S', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('S', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 4::numeric, 'zones', 'p25-t4'),
      ('S', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 4::numeric, 'zones', 'p25-t4'),
      ('S', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('S', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 2::numeric, 'zones', 'p25-t4'),
      ('S', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('S', 2024, null::int, 'water_zones_by_hours', '24 hrs', 4::numeric, 'zones', 'p25-t4'),
      ('S', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      ('T', 2024, null::int, 'water_supply_zones', null, 4::numeric, 'zones', 'p25-t4'),
      ('T', 2024, null::int, 'water_supply_hours', null, 24::numeric, 'hours/day', 'p25-t4'),
      ('T', 2024, null::int, 'water_zones_by_hours', '<=2 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('T', 2024, null::int, 'water_zones_by_hours', '>2 to <=4 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('T', 2024, null::int, 'water_zones_by_hours', '>4 to <=8 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('T', 2024, null::int, 'water_zones_by_hours', '>8 to <=12 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('T', 2024, null::int, 'water_zones_by_hours', '>12 to <=18 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('T', 2024, null::int, 'water_zones_by_hours', '>18 to <24 hrs', 0::numeric, 'zones', 'p25-t4'),
      ('T', 2024, null::int, 'water_zones_by_hours', '24 hrs', 4::numeric, 'zones', 'p25-t4'),
      ('T', 2024, null::int, 'water_zones_by_hours', 'Not available', 0::numeric, 'zones', 'p25-t4'),
      (null, 2024, null::int, 'water_supply_hours', null, 5.37::numeric, 'hours/day', 'p25-t4'),
      ('A', 2020, null::int, 'water_unfit_samples_pct', null, 0.84::numeric, '%', 'p25-t7'),
      ('A', 2021, null::int, 'water_unfit_samples_pct', null, 0.23::numeric, '%', 'p25-t7'),
      ('A', 2022, null::int, 'water_unfit_samples_pct', null, 0.84::numeric, '%', 'p25-t7'),
      ('A', 2023, null::int, 'water_unfit_samples_pct', null, 2.6::numeric, '%', 'p25-t7'),
      ('A', 2024, null::int, 'water_unfit_samples_pct', null, 1.4::numeric, '%', 'p25-t7'),
      ('B', 2020, null::int, 'water_unfit_samples_pct', null, 1.49::numeric, '%', 'p25-t7'),
      ('B', 2021, null::int, 'water_unfit_samples_pct', null, 1.5::numeric, '%', 'p25-t7'),
      ('B', 2022, null::int, 'water_unfit_samples_pct', null, 5.97::numeric, '%', 'p25-t7'),
      ('B', 2023, null::int, 'water_unfit_samples_pct', null, 1.59::numeric, '%', 'p25-t7'),
      ('B', 2024, null::int, 'water_unfit_samples_pct', null, 2.9::numeric, '%', 'p25-t7'),
      ('C', 2020, null::int, 'water_unfit_samples_pct', null, 0.18::numeric, '%', 'p25-t7'),
      ('C', 2021, null::int, 'water_unfit_samples_pct', null, 0.17::numeric, '%', 'p25-t7'),
      ('C', 2022, null::int, 'water_unfit_samples_pct', null, 0.46::numeric, '%', 'p25-t7'),
      ('C', 2023, null::int, 'water_unfit_samples_pct', null, 0.3::numeric, '%', 'p25-t7'),
      ('C', 2024, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('D', 2020, null::int, 'water_unfit_samples_pct', null, 1.57::numeric, '%', 'p25-t7'),
      ('D', 2021, null::int, 'water_unfit_samples_pct', null, 0.62::numeric, '%', 'p25-t7'),
      ('D', 2022, null::int, 'water_unfit_samples_pct', null, 1.18::numeric, '%', 'p25-t7'),
      ('D', 2023, null::int, 'water_unfit_samples_pct', null, 0.71::numeric, '%', 'p25-t7'),
      ('D', 2024, null::int, 'water_unfit_samples_pct', null, 0.35::numeric, '%', 'p25-t7'),
      ('E', 2020, null::int, 'water_unfit_samples_pct', null, 0.93::numeric, '%', 'p25-t7'),
      ('E', 2021, null::int, 'water_unfit_samples_pct', null, 0.19::numeric, '%', 'p25-t7'),
      ('E', 2022, null::int, 'water_unfit_samples_pct', null, 1.16::numeric, '%', 'p25-t7'),
      ('E', 2023, null::int, 'water_unfit_samples_pct', null, 0.54::numeric, '%', 'p25-t7'),
      ('E', 2024, null::int, 'water_unfit_samples_pct', null, 0.09::numeric, '%', 'p25-t7'),
      ('F/N', 2020, null::int, 'water_unfit_samples_pct', null, 2.2::numeric, '%', 'p25-t7'),
      ('F/N', 2021, null::int, 'water_unfit_samples_pct', null, 0.07::numeric, '%', 'p25-t7'),
      ('F/N', 2022, null::int, 'water_unfit_samples_pct', null, 0.48::numeric, '%', 'p25-t7'),
      ('F/N', 2023, null::int, 'water_unfit_samples_pct', null, 0.09::numeric, '%', 'p25-t7'),
      ('F/N', 2024, null::int, 'water_unfit_samples_pct', null, 0.14::numeric, '%', 'p25-t7'),
      ('F/S', 2020, null::int, 'water_unfit_samples_pct', null, 1.89::numeric, '%', 'p25-t7'),
      ('F/S', 2021, null::int, 'water_unfit_samples_pct', null, 1.92::numeric, '%', 'p25-t7'),
      ('F/S', 2022, null::int, 'water_unfit_samples_pct', null, 0.16::numeric, '%', 'p25-t7'),
      ('F/S', 2023, null::int, 'water_unfit_samples_pct', null, 0.41::numeric, '%', 'p25-t7'),
      ('F/S', 2024, null::int, 'water_unfit_samples_pct', null, 0.09::numeric, '%', 'p25-t7'),
      ('G/N', 2020, null::int, 'water_unfit_samples_pct', null, 4.02::numeric, '%', 'p25-t7'),
      ('G/N', 2021, null::int, 'water_unfit_samples_pct', null, 0.91::numeric, '%', 'p25-t7'),
      ('G/N', 2022, null::int, 'water_unfit_samples_pct', null, 0.3::numeric, '%', 'p25-t7'),
      ('G/N', 2023, null::int, 'water_unfit_samples_pct', null, 1.33::numeric, '%', 'p25-t7'),
      ('G/N', 2024, null::int, 'water_unfit_samples_pct', null, 0.23::numeric, '%', 'p25-t7'),
      ('G/S', 2020, null::int, 'water_unfit_samples_pct', null, 0.84::numeric, '%', 'p25-t7'),
      ('G/S', 2021, null::int, 'water_unfit_samples_pct', null, 0.22::numeric, '%', 'p25-t7'),
      ('G/S', 2022, null::int, 'water_unfit_samples_pct', null, 1.5::numeric, '%', 'p25-t7'),
      ('G/S', 2023, null::int, 'water_unfit_samples_pct', null, 0.28::numeric, '%', 'p25-t7'),
      ('G/S', 2024, null::int, 'water_unfit_samples_pct', null, 0.49::numeric, '%', 'p25-t7'),
      ('H/E', 2020, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('H/E', 2021, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('H/E', 2022, null::int, 'water_unfit_samples_pct', null, 0.94::numeric, '%', 'p25-t7'),
      ('H/E', 2023, null::int, 'water_unfit_samples_pct', null, 2.24::numeric, '%', 'p25-t7'),
      ('H/E', 2024, null::int, 'water_unfit_samples_pct', null, 1.62::numeric, '%', 'p25-t7'),
      ('H/W', 2020, null::int, 'water_unfit_samples_pct', null, 1.55::numeric, '%', 'p25-t7'),
      ('H/W', 2021, null::int, 'water_unfit_samples_pct', null, 0.21::numeric, '%', 'p25-t7'),
      ('H/W', 2022, null::int, 'water_unfit_samples_pct', null, 0.3::numeric, '%', 'p25-t7'),
      ('H/W', 2023, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('H/W', 2024, null::int, 'water_unfit_samples_pct', null, 0.56::numeric, '%', 'p25-t7'),
      ('K/E', 2020, null::int, 'water_unfit_samples_pct', null, 0.82::numeric, '%', 'p25-t7'),
      ('K/E', 2021, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('K/E', 2022, null::int, 'water_unfit_samples_pct', null, 0.2::numeric, '%', 'p25-t7'),
      ('K/E', 2023, null::int, 'water_unfit_samples_pct', null, 0.1::numeric, '%', 'p25-t7'),
      ('K/E', 2024, null::int, 'water_unfit_samples_pct', null, 0.22::numeric, '%', 'p25-t7'),
      ('K/W', 2020, null::int, 'water_unfit_samples_pct', null, 0.5::numeric, '%', 'p25-t7'),
      ('K/W', 2021, null::int, 'water_unfit_samples_pct', null, 0.15::numeric, '%', 'p25-t7'),
      ('K/W', 2022, null::int, 'water_unfit_samples_pct', null, 0.15::numeric, '%', 'p25-t7'),
      ('K/W', 2023, null::int, 'water_unfit_samples_pct', null, 0.34::numeric, '%', 'p25-t7'),
      ('K/W', 2024, null::int, 'water_unfit_samples_pct', null, 0.17::numeric, '%', 'p25-t7'),
      ('L', 2020, null::int, 'water_unfit_samples_pct', null, 1.06::numeric, '%', 'p25-t7'),
      ('L', 2021, null::int, 'water_unfit_samples_pct', null, 0.48::numeric, '%', 'p25-t7'),
      ('L', 2022, null::int, 'water_unfit_samples_pct', null, 1.04::numeric, '%', 'p25-t7'),
      ('L', 2023, null::int, 'water_unfit_samples_pct', null, 0.61::numeric, '%', 'p25-t7'),
      ('L', 2024, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('M/E', 2020, null::int, 'water_unfit_samples_pct', null, 2.15::numeric, '%', 'p25-t7'),
      ('M/E', 2021, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('M/E', 2022, null::int, 'water_unfit_samples_pct', null, 0.69::numeric, '%', 'p25-t7'),
      ('M/E', 2023, null::int, 'water_unfit_samples_pct', null, 0.31::numeric, '%', 'p25-t7'),
      ('M/E', 2024, null::int, 'water_unfit_samples_pct', null, 0.46::numeric, '%', 'p25-t7'),
      ('M/W', 2020, null::int, 'water_unfit_samples_pct', null, 1.68::numeric, '%', 'p25-t7'),
      ('M/W', 2021, null::int, 'water_unfit_samples_pct', null, 0.5::numeric, '%', 'p25-t7'),
      ('M/W', 2022, null::int, 'water_unfit_samples_pct', null, 0.51::numeric, '%', 'p25-t7'),
      ('M/W', 2023, null::int, 'water_unfit_samples_pct', null, 0.71::numeric, '%', 'p25-t7'),
      ('M/W', 2024, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('N', 2020, null::int, 'water_unfit_samples_pct', null, 1.22::numeric, '%', 'p25-t7'),
      ('N', 2021, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('N', 2022, null::int, 'water_unfit_samples_pct', null, 0.78::numeric, '%', 'p25-t7'),
      ('N', 2023, null::int, 'water_unfit_samples_pct', null, 0.27::numeric, '%', 'p25-t7'),
      ('N', 2024, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('P/N', 2020, null::int, 'water_unfit_samples_pct', null, 0.4::numeric, '%', 'p25-t7'),
      ('P/N', 2021, null::int, 'water_unfit_samples_pct', null, 0.06::numeric, '%', 'p25-t7'),
      ('P/N', 2022, null::int, 'water_unfit_samples_pct', null, 0.17::numeric, '%', 'p25-t7'),
      ('P/N', 2023, null::int, 'water_unfit_samples_pct', null, 0.09::numeric, '%', 'p25-t7'),
      ('P/N', 2024, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('P/S', 2020, null::int, 'water_unfit_samples_pct', null, 2.39::numeric, '%', 'p25-t7'),
      ('P/S', 2021, null::int, 'water_unfit_samples_pct', null, 0.09::numeric, '%', 'p25-t7'),
      ('P/S', 2022, null::int, 'water_unfit_samples_pct', null, 0.36::numeric, '%', 'p25-t7'),
      ('P/S', 2023, null::int, 'water_unfit_samples_pct', null, 0.3::numeric, '%', 'p25-t7'),
      ('P/S', 2024, null::int, 'water_unfit_samples_pct', null, 0.05::numeric, '%', 'p25-t7'),
      ('R/C', 2020, null::int, 'water_unfit_samples_pct', null, 1.42::numeric, '%', 'p25-t7'),
      ('R/C', 2021, null::int, 'water_unfit_samples_pct', null, 0.82::numeric, '%', 'p25-t7'),
      ('R/C', 2022, null::int, 'water_unfit_samples_pct', null, 1.98::numeric, '%', 'p25-t7'),
      ('R/C', 2023, null::int, 'water_unfit_samples_pct', null, 0.36::numeric, '%', 'p25-t7'),
      ('R/C', 2024, null::int, 'water_unfit_samples_pct', null, 0.61::numeric, '%', 'p25-t7'),
      ('R/N', 2020, null::int, 'water_unfit_samples_pct', null, 0.68::numeric, '%', 'p25-t7'),
      ('R/N', 2021, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('R/N', 2022, null::int, 'water_unfit_samples_pct', null, 0.31::numeric, '%', 'p25-t7'),
      ('R/N', 2023, null::int, 'water_unfit_samples_pct', null, 0.16::numeric, '%', 'p25-t7'),
      ('R/N', 2024, null::int, 'water_unfit_samples_pct', null, 0.0::numeric, '%', 'p25-t7'),
      ('R/S', 2020, null::int, 'water_unfit_samples_pct', null, 0.5::numeric, '%', 'p25-t7'),
      ('R/S', 2021, null::int, 'water_unfit_samples_pct', null, 0.26::numeric, '%', 'p25-t7'),
      ('R/S', 2022, null::int, 'water_unfit_samples_pct', null, 0.57::numeric, '%', 'p25-t7'),
      ('R/S', 2023, null::int, 'water_unfit_samples_pct', null, 0.31::numeric, '%', 'p25-t7'),
      ('R/S', 2024, null::int, 'water_unfit_samples_pct', null, 0.16::numeric, '%', 'p25-t7'),
      ('S', 2020, null::int, 'water_unfit_samples_pct', null, 0.94::numeric, '%', 'p25-t7'),
      ('S', 2021, null::int, 'water_unfit_samples_pct', null, 0.14::numeric, '%', 'p25-t7'),
      ('S', 2022, null::int, 'water_unfit_samples_pct', null, 0.07::numeric, '%', 'p25-t7'),
      ('S', 2023, null::int, 'water_unfit_samples_pct', null, 0.14::numeric, '%', 'p25-t7'),
      ('S', 2024, null::int, 'water_unfit_samples_pct', null, 0.08::numeric, '%', 'p25-t7'),
      ('T', 2020, null::int, 'water_unfit_samples_pct', null, 2.32::numeric, '%', 'p25-t7'),
      ('T', 2021, null::int, 'water_unfit_samples_pct', null, 0.11::numeric, '%', 'p25-t7'),
      ('T', 2022, null::int, 'water_unfit_samples_pct', null, 0.1::numeric, '%', 'p25-t7'),
      ('T', 2023, null::int, 'water_unfit_samples_pct', null, 1.08::numeric, '%', 'p25-t7'),
      ('T', 2024, null::int, 'water_unfit_samples_pct', null, 0.81::numeric, '%', 'p25-t7'),
      (null, 2020, null::int, 'water_unfit_samples_pct', null, 1.02::numeric, '%', 'p25-t7'),
      (null, 2021, null::int, 'water_unfit_samples_pct', null, 0.29::numeric, '%', 'p25-t7'),
      (null, 2022, null::int, 'water_unfit_samples_pct', null, 0.67::numeric, '%', 'p25-t7'),
      (null, 2023, null::int, 'water_unfit_samples_pct', null, 0.54::numeric, '%', 'p25-t7'),
      (null, 2024, null::int, 'water_unfit_samples_pct', null, 0.33::numeric, '%', 'p25-t7'),
      (null, 2024, null::int, 'water_yield_mld', null, 4370::numeric, 'MLD', 'p25-t1'),
      (null, 2024, null::int, 'water_enroute_loss_mld', null, 395::numeric, 'MLD', 'p25-t1'),
      (null, 2024, null::int, 'water_supply_mld', null, 3975::numeric, 'MLD', 'p25-t1'),
      (null, 2024, null::int, 'water_gap_mld', null, 689::numeric, 'MLD', 'p25-t1'),
      (null, 2024, null::int, 'water_demand_mld', null, 4664::numeric, 'MLD', 'p25-t1')
    ) as v(zone_code, year, month, metric, category, value, unit, source_id)
    left join city_zones z on z.organization_id = p_org and z.code = v.zone_code;

  -- 2025 ward populations as printed in the report (from BMC's Environment Status Report 2024-25)
  update city_zones z set population = ci.value::int
    from civic_indicators ci
   where ci.zone_id = z.id and ci.metric = 'population' and z.organization_id = p_org;

  perform app.compute_health_index(p_org, 2025);
  perform app.load_mumbai_models(p_org);      -- defined in 0009

  return jsonb_build_object(
    'wards',      (select count(*) from city_zones where organization_id = p_org),
    'indicators', (select count(*) from civic_indicators where organization_id = p_org),
    'sources',    (select count(*) from data_sources where organization_id = p_org),
    'models',     (select count(*) from ml_models where organization_id = p_org));
end $fn$;

revoke all on function app.load_mumbai_data(uuid) from public, anon, authenticated;

-- ============================================================================
-- 0009_mumbai_models.sql
-- ============================================================================
-- CivicOS 0009: Mumbai model results. GENERATED by data/mumbai/ml/build_ml_sql.py - do not edit by hand.
-- Trained on the published figures in 0008 by data/mumbai/ml/train.py (deterministic: re-running gives the same results).

create or replace function app.load_mumbai_models(p_org uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
begin
  delete from ml_models where organization_id = p_org;   -- cascades to clusters and forecasts

  insert into ml_models (organization_id, id, name, kind, method, description, params, metrics, trained_on, trained_at) values
    (p_org, 'ward-groups-2025', 'Ward groups', 'clustering', 'k-means (scikit-learn), features standardised; water hours log-transformed', 'Groups wards that look alike across complaints, resolution, water and waste. Unsupervised: there are no right answers to train against, so it describes patterns rather than predicting anything.', '{"k":2,"features":[{"key":"complaints_per_10k","label":"Complaints per 10,000 residents (2025)","higher_is_better":false},{"key":"closed_pct","label":"Complaints closed, % (2025)","higher_is_better":true},{"key":"avg_days","label":"Average days to close (2025)","higher_is_better":false},{"key":"water_hours","label":"Water supply, hours per day (2024)","higher_is_better":true},{"key":"water_unfit_pct","label":"Drinking-water samples unfit, % (2024)","higher_is_better":false},{"key":"waste_per_capita","label":"Waste per person, kg per day (2025)","higher_is_better":null},{"key":"slum_pct","label":"Slum population, % (2011)","higher_is_better":null}],"n_init":50,"random_state":42,"groups":[{"cluster":1,"wards":["D","E","F/N","F/S","G/N","G/S","H/E","K/E","K/W","L","M/E","M/W","N","P/N","P/S","R/C","R/N","R/S","S","T"],"mean":{"complaints_per_10k":88.53,"closed_pct":97.9,"avg_days":28.45,"water_hours":6.62,"water_unfit_pct":0.28,"waste_per_capita":0.35,"slum_pct":40.8},"z":{"complaints_per_10k":-0.32,"closed_pct":0.18,"avg_days":-0.11,"water_hours":0.15,"water_unfit_pct":-0.24,"waste_per_capita":-0.36,"slum_pct":0.17},"label":"Low waste per person, few complaints"},{"cluster":2,"wards":["A","B","C","H/W"],"mean":{"complaints_per_10k":171.37,"closed_pct":94.66,"avg_days":37.5,"water_hours":2.28,"water_unfit_pct":1.21,"waste_per_capita":0.61,"slum_pct":21.0},"z":{"complaints_per_10k":1.62,"closed_pct":-0.88,"avg_days":0.56,"water_hours":-0.74,"water_unfit_pct":1.18,"waste_per_capita":1.78,"slum_pct":-0.87},"label":"High waste per person, many complaints"}]}'::jsonb, '{"silhouette":0.353,"candidates":{"2":{"silhouette":0.353,"smallest_group":4},"3":{"silhouette":0.185,"smallest_group":4},"4":{"silhouette":0.191,"smallest_group":1},"5":{"silhouette":0.203,"smallest_group":1}}}'::jsonb, '24 wards; Praja Foundation 2026 report Tables 3, 11, 43; 2025 report Tables 4, 7', '2026-11-14'::date),
    (p_org, 'complaints-forecast-2026', 'Complaint forecasts', 'forecast', 'Per family of series, the best of three simple methods by rolling backtest; 80% interval from that method''s backtest errors', 'Predicts how many complaints will be registered in 2026, with a range. Built on ten yearly figures per series, so the ranges are wide on purpose.', '{"methods":{"naive":"Last year''s value","mean3":"Average of the last three years","trend":"Straight-line trend over all earlier years"},"backtest_years":[2022,2023,2024,2025],"families":{"ward_total":{"label":"All complaints, by ward","series":24,"backtest_years":[2022,2023,2024,2025],"chosen":"trend","mape_pct":{"naive":11.7,"mean3":11.5,"trend":9.7},"mae":{"naive":590.8,"mean3":589.1,"trend":489.6},"interval_pct":14.2,"baseline":"naive","improvement_vs_naive_pct":17.1},"ward_swm":{"label":"Solid waste complaints, by ward","series":24,"backtest_years":[2022,2023,2024,2025],"chosen":"naive","mape_pct":{"naive":23.4,"mean3":28.3,"trend":23.9},"mae":{"naive":239.7,"mean3":307.6,"trend":244.2},"interval_pct":43.6,"baseline":"naive","improvement_vs_naive_pct":0.0},"ward_drainage":{"label":"Drainage complaints, by ward","series":24,"backtest_years":[2022,2023,2024,2025],"chosen":"naive","mape_pct":{"naive":22.2,"mean3":30.5,"trend":32.0},"mae":{"naive":118.4,"mean3":122.9,"trend":120.7},"interval_pct":27.4,"baseline":"naive","improvement_vs_naive_pct":0.0},"city_issue":{"label":"City complaints, by issue","series":18,"backtest_years":[2022,2023,2024,2025],"chosen":"mean3","mape_pct":{"naive":16.8,"mean3":16.5,"trend":18.6},"mae":{"naive":903.2,"mean3":1036.6,"trend":1038.4},"interval_pct":25.7,"baseline":"naive","improvement_vs_naive_pct":1.8},"city_total":{"label":"City complaints, all issues","series":1,"backtest_years":[2022,2023,2024,2025],"chosen":"trend","mape_pct":{"naive":10.6,"mean3":10.6,"trend":5.8},"mae":{"naive":12404.0,"mean3":12903.6,"trend":7153.0},"interval_pct":10.2,"baseline":"naive","improvement_vs_naive_pct":45.3}}}'::jsonb, '{"ward_total":{"mape_pct":9.7,"naive_mape_pct":11.7},"ward_swm":{"mape_pct":23.4,"naive_mape_pct":23.4},"ward_drainage":{"mape_pct":22.2,"naive_mape_pct":22.2},"city_issue":{"mape_pct":16.5,"naive_mape_pct":16.8},"city_total":{"mape_pct":5.8,"naive_mape_pct":10.6}}'::jsonb, 'Complaints registered 2016-2025; Praja Foundation 2026 report Tables 1, 39, 41, 43', '2026-11-14'::date);

  insert into ml_ward_clusters (organization_id, model_id, zone_id, cluster, features, z)
  select p_org, 'ward-groups-2025', z.id, v.cluster, v.features, v.z
    from (values
      ('A', 2, '{"complaints_per_10k":102.0,"closed_pct":99.2,"avg_days":49,"water_hours":2.46,"water_unfit_pct":1.4,"waste_per_capita":0.64,"slum_pct":34}'::jsonb, '{"complaints_per_10k":-0.01,"closed_pct":0.6,"avg_days":1.42,"water_hours":-0.7,"water_unfit_pct":1.45,"waste_per_capita":2.02,"slum_pct":-0.18}'::jsonb),
      ('B', 2, '{"complaints_per_10k":227.08,"closed_pct":88.64,"avg_days":52,"water_hours":1.88,"water_unfit_pct":2.9,"waste_per_capita":0.54,"slum_pct":11}'::jsonb, '{"complaints_per_10k":2.93,"closed_pct":-2.84,"avg_days":1.64,"water_hours":-0.82,"water_unfit_pct":3.71,"waste_per_capita":1.21,"slum_pct":-1.39}'::jsonb),
      ('C', 2, '{"complaints_per_10k":204.01,"closed_pct":93.81,"avg_days":26,"water_hours":1.53,"water_unfit_pct":0.0,"waste_per_capita":0.66,"slum_pct":0}'::jsonb, '{"complaints_per_10k":2.39,"closed_pct":-1.16,"avg_days":-0.3,"water_hours":-0.89,"water_unfit_pct":-0.65,"waste_per_capita":2.19,"slum_pct":-1.97}'::jsonb),
      ('D', 1, '{"complaints_per_10k":105.56,"closed_pct":92.4,"avg_days":14,"water_hours":3.5,"water_unfit_pct":0.35,"waste_per_capita":0.28,"slum_pct":10}'::jsonb, '{"complaints_per_10k":0.08,"closed_pct":-1.62,"avg_days":-1.19,"water_hours":-0.49,"water_unfit_pct":-0.13,"waste_per_capita":-0.9,"slum_pct":-1.45}'::jsonb),
      ('E', 1, '{"complaints_per_10k":105.99,"closed_pct":99.36,"avg_days":38,"water_hours":4.87,"water_unfit_pct":0.09,"waste_per_capita":0.32,"slum_pct":20}'::jsonb, '{"complaints_per_10k":0.09,"closed_pct":0.65,"avg_days":0.6,"water_hours":-0.21,"water_unfit_pct":-0.52,"waste_per_capita":-0.57,"slum_pct":-0.92}'::jsonb),
      ('F/N', 1, '{"complaints_per_10k":73.12,"closed_pct":98.48,"avg_days":41,"water_hours":3.3,"water_unfit_pct":0.14,"waste_per_capita":0.3,"slum_pct":58}'::jsonb, '{"complaints_per_10k":-0.69,"closed_pct":0.36,"avg_days":0.82,"water_hours":-0.53,"water_unfit_pct":-0.44,"waste_per_capita":-0.73,"slum_pct":1.08}'::jsonb),
      ('F/S', 1, '{"complaints_per_10k":72.03,"closed_pct":98.36,"avg_days":24,"water_hours":5.03,"water_unfit_pct":0.09,"waste_per_capita":0.31,"slum_pct":26}'::jsonb, '{"complaints_per_10k":-0.71,"closed_pct":0.32,"avg_days":-0.44,"water_hours":-0.18,"water_unfit_pct":-0.52,"waste_per_capita":-0.65,"slum_pct":-0.6}'::jsonb),
      ('G/N', 1, '{"complaints_per_10k":78.0,"closed_pct":90.17,"avg_days":43,"water_hours":4.25,"water_unfit_pct":0.23,"waste_per_capita":0.42,"slum_pct":32}'::jsonb, '{"complaints_per_10k":-0.57,"closed_pct":-2.34,"avg_days":0.97,"water_hours":-0.34,"water_unfit_pct":-0.31,"waste_per_capita":0.24,"slum_pct":-0.29}'::jsonb),
      ('G/S', 1, '{"complaints_per_10k":79.26,"closed_pct":99.75,"avg_days":44,"water_hours":5.53,"water_unfit_pct":0.49,"waste_per_capita":0.27,"slum_pct":21}'::jsonb, '{"complaints_per_10k":-0.54,"closed_pct":0.78,"avg_days":1.05,"water_hours":-0.08,"water_unfit_pct":0.08,"waste_per_capita":-0.98,"slum_pct":-0.87}'::jsonb),
      ('H/E', 1, '{"complaints_per_10k":65.67,"closed_pct":97.87,"avg_days":32,"water_hours":3.11,"water_unfit_pct":1.62,"waste_per_capita":0.3,"slum_pct":42}'::jsonb, '{"complaints_per_10k":-0.86,"closed_pct":0.16,"avg_days":0.15,"water_hours":-0.57,"water_unfit_pct":1.79,"waste_per_capita":-0.73,"slum_pct":0.24}'::jsonb),
      ('H/W', 2, '{"complaints_per_10k":152.4,"closed_pct":96.98,"avg_days":23,"water_hours":3.25,"water_unfit_pct":0.56,"waste_per_capita":0.6,"slum_pct":39}'::jsonb, '{"complaints_per_10k":1.18,"closed_pct":-0.12,"avg_days":-0.52,"water_hours":-0.54,"water_unfit_pct":0.19,"waste_per_capita":1.7,"slum_pct":0.08}'::jsonb),
      ('K/E', 1, '{"complaints_per_10k":109.16,"closed_pct":99.32,"avg_days":33,"water_hours":6.48,"water_unfit_pct":0.22,"waste_per_capita":0.37,"slum_pct":49}'::jsonb, '{"complaints_per_10k":0.16,"closed_pct":0.64,"avg_days":0.23,"water_hours":0.12,"water_unfit_pct":-0.32,"waste_per_capita":-0.17,"slum_pct":0.6}'::jsonb),
      ('K/W', 1, '{"complaints_per_10k":97.91,"closed_pct":98.47,"avg_days":45,"water_hours":2.37,"water_unfit_pct":0.17,"waste_per_capita":0.39,"slum_pct":15}'::jsonb, '{"complaints_per_10k":-0.1,"closed_pct":0.36,"avg_days":1.12,"water_hours":-0.72,"water_unfit_pct":-0.4,"waste_per_capita":-0.0,"slum_pct":-1.18}'::jsonb),
      ('L', 1, '{"complaints_per_10k":73.19,"closed_pct":97.53,"avg_days":33,"water_hours":10.56,"water_unfit_pct":0.0,"waste_per_capita":0.39,"slum_pct":54}'::jsonb, '{"complaints_per_10k":-0.68,"closed_pct":0.05,"avg_days":0.23,"water_hours":0.95,"water_unfit_pct":-0.65,"waste_per_capita":-0.0,"slum_pct":0.87}'::jsonb),
      ('M/E', 1, '{"complaints_per_10k":52.37,"closed_pct":98.41,"avg_days":19,"water_hours":7.56,"water_unfit_pct":0.46,"waste_per_capita":0.47,"slum_pct":30}'::jsonb, '{"complaints_per_10k":-1.17,"closed_pct":0.34,"avg_days":-0.82,"water_hours":0.34,"water_unfit_pct":0.04,"waste_per_capita":0.65,"slum_pct":-0.39}'::jsonb),
      ('M/W', 1, '{"complaints_per_10k":92.63,"closed_pct":98.78,"avg_days":20,"water_hours":11,"water_unfit_pct":0.0,"waste_per_capita":0.54,"slum_pct":53}'::jsonb, '{"complaints_per_10k":-0.23,"closed_pct":0.46,"avg_days":-0.74,"water_hours":1.04,"water_unfit_pct":-0.65,"waste_per_capita":1.21,"slum_pct":0.82}'::jsonb),
      ('N', 1, '{"complaints_per_10k":98.53,"closed_pct":94.25,"avg_days":16,"water_hours":11.83,"water_unfit_pct":0.0,"waste_per_capita":0.29,"slum_pct":62}'::jsonb, '{"complaints_per_10k":-0.09,"closed_pct":-1.01,"avg_days":-1.04,"water_hours":1.21,"water_unfit_pct":-0.65,"waste_per_capita":-0.81,"slum_pct":1.29}'::jsonb),
      ('P/N', 1, '{"complaints_per_10k":78.49,"closed_pct":98.91,"avg_days":56,"water_hours":3.89,"water_unfit_pct":0.0,"waste_per_capita":0.31,"slum_pct":54}'::jsonb, '{"complaints_per_10k":-0.56,"closed_pct":0.5,"avg_days":1.94,"water_hours":-0.41,"water_unfit_pct":-0.65,"waste_per_capita":-0.65,"slum_pct":0.87}'::jsonb),
      ('P/S', 1, '{"complaints_per_10k":104.9,"closed_pct":99.45,"avg_days":35,"water_hours":2.73,"water_unfit_pct":0.05,"waste_per_capita":0.39,"slum_pct":57}'::jsonb, '{"complaints_per_10k":0.06,"closed_pct":0.68,"avg_days":0.38,"water_hours":-0.65,"water_unfit_pct":-0.58,"waste_per_capita":-0.0,"slum_pct":1.03}'::jsonb),
      ('R/C', 1, '{"complaints_per_10k":92.17,"closed_pct":98.9,"avg_days":19,"water_hours":3.54,"water_unfit_pct":0.61,"waste_per_capita":0.29,"slum_pct":19}'::jsonb, '{"complaints_per_10k":-0.24,"closed_pct":0.5,"avg_days":-0.82,"water_hours":-0.48,"water_unfit_pct":0.26,"waste_per_capita":-0.81,"slum_pct":-0.97}'::jsonb),
      ('R/N', 1, '{"complaints_per_10k":69.89,"closed_pct":99.81,"avg_days":19,"water_hours":2.46,"water_unfit_pct":0.0,"waste_per_capita":0.26,"slum_pct":51}'::jsonb, '{"complaints_per_10k":-0.76,"closed_pct":0.8,"avg_days":-0.82,"water_hours":-0.7,"water_unfit_pct":-0.65,"waste_per_capita":-1.06,"slum_pct":0.71}'::jsonb),
      ('R/S', 1, '{"complaints_per_10k":70.33,"closed_pct":99.53,"avg_days":13,"water_hours":4.48,"water_unfit_pct":0.16,"waste_per_capita":0.22,"slum_pct":58}'::jsonb, '{"complaints_per_10k":-0.75,"closed_pct":0.71,"avg_days":-1.26,"water_hours":-0.29,"water_unfit_pct":-0.41,"waste_per_capita":-1.38,"slum_pct":1.08}'::jsonb),
      ('S', 1, '{"complaints_per_10k":167.4,"closed_pct":98.34,"avg_days":18,"water_hours":12,"water_unfit_pct":0.08,"waste_per_capita":0.35,"slum_pct":72}'::jsonb, '{"complaints_per_10k":1.53,"closed_pct":0.32,"avg_days":-0.89,"water_hours":1.25,"water_unfit_pct":-0.53,"waste_per_capita":-0.33,"slum_pct":1.81}'::jsonb),
      ('T', 1, '{"complaints_per_10k":83.98,"closed_pct":100.0,"avg_days":7,"water_hours":24,"water_unfit_pct":0.81,"waste_per_capita":0.46,"slum_pct":33}'::jsonb, '{"complaints_per_10k":-0.43,"closed_pct":0.86,"avg_days":-1.71,"water_hours":3.69,"water_unfit_pct":0.57,"waste_per_capita":0.56,"slum_pct":-0.24}'::jsonb)
    ) as v(code, cluster, features, z)
    join city_zones z on z.organization_id = p_org and z.code = v.code;

  insert into ml_forecasts (organization_id, model_id, zone_id, category, year, value, lower, upper, method, family)
  select p_org, 'complaints-forecast-2026', z.id, v.category, v.year, v.value, v.lower, v.upper, v.method, v.family
    from (values
      ('A', null, 2026, 2483::numeric, 2130::numeric, 2835::numeric, 'trend', 'ward_total'),
      ('B', null, 2026, 3311::numeric, 2841::numeric, 3781::numeric, 'trend', 'ward_total'),
      ('C', null, 2026, 3694::numeric, 3170::numeric, 4219::numeric, 'trend', 'ward_total'),
      ('D', null, 2026, 3574::numeric, 3067::numeric, 4082::numeric, 'trend', 'ward_total'),
      ('E', null, 2026, 4666::numeric, 4003::numeric, 5328::numeric, 'trend', 'ward_total'),
      ('F/N', null, 2026, 4457::numeric, 3824::numeric, 5090::numeric, 'trend', 'ward_total'),
      ('F/S', null, 2026, 3140::numeric, 2694::numeric, 3586::numeric, 'trend', 'ward_total'),
      ('G/N', null, 2026, 5210::numeric, 4470::numeric, 5950::numeric, 'trend', 'ward_total'),
      ('G/S', null, 2026, 3309::numeric, 2839::numeric, 3779::numeric, 'trend', 'ward_total'),
      ('H/E', null, 2026, 4338::numeric, 3722::numeric, 4954::numeric, 'trend', 'ward_total'),
      ('H/W', null, 2026, 5309::numeric, 4555::numeric, 6062::numeric, 'trend', 'ward_total'),
      ('K/E', null, 2026, 9023::numeric, 7742::numeric, 10304::numeric, 'trend', 'ward_total'),
      ('K/W', null, 2026, 8328::numeric, 7146::numeric, 9511::numeric, 'trend', 'ward_total'),
      ('L', null, 2026, 6849::numeric, 5877::numeric, 7822::numeric, 'trend', 'ward_total'),
      ('M/E', null, 2026, 4511::numeric, 3871::numeric, 5152::numeric, 'trend', 'ward_total'),
      ('M/W', null, 2026, 4358::numeric, 3739::numeric, 4976::numeric, 'trend', 'ward_total'),
      ('N', null, 2026, 5946::numeric, 5102::numeric, 6791::numeric, 'trend', 'ward_total'),
      ('P/N', null, 2026, 8108::numeric, 6957::numeric, 9259::numeric, 'trend', 'ward_total'),
      ('P/S', null, 2026, 4852::numeric, 4163::numeric, 5541::numeric, 'trend', 'ward_total'),
      ('R/C', null, 2026, 5758::numeric, 4940::numeric, 6576::numeric, 'trend', 'ward_total'),
      ('R/N', null, 2026, 3309::numeric, 2840::numeric, 3779::numeric, 'trend', 'ward_total'),
      ('R/S', null, 2026, 5156::numeric, 4424::numeric, 5888::numeric, 'trend', 'ward_total'),
      ('S', null, 2026, 9499::numeric, 8150::numeric, 10848::numeric, 'trend', 'ward_total'),
      ('T', null, 2026, 3025::numeric, 2596::numeric, 3455::numeric, 'trend', 'ward_total'),
      ('A', 'Solid Waste Management (SWM)', 2026, 364::numeric, 205::numeric, 523::numeric, 'naive', 'ward_swm'),
      ('B', 'Solid Waste Management (SWM)', 2026, 553::numeric, 312::numeric, 794::numeric, 'naive', 'ward_swm'),
      ('C', 'Solid Waste Management (SWM)', 2026, 1208::numeric, 682::numeric, 1734::numeric, 'naive', 'ward_swm'),
      ('D', 'Solid Waste Management (SWM)', 2026, 803::numeric, 453::numeric, 1153::numeric, 'naive', 'ward_swm'),
      ('E', 'Solid Waste Management (SWM)', 2026, 1559::numeric, 880::numeric, 2238::numeric, 'naive', 'ward_swm'),
      ('F/N', 'Solid Waste Management (SWM)', 2026, 1198::numeric, 676::numeric, 1720::numeric, 'naive', 'ward_swm'),
      ('F/S', 'Solid Waste Management (SWM)', 2026, 526::numeric, 297::numeric, 755::numeric, 'naive', 'ward_swm'),
      ('G/N', 'Solid Waste Management (SWM)', 2026, 1315::numeric, 742::numeric, 1888::numeric, 'naive', 'ward_swm'),
      ('G/S', 'Solid Waste Management (SWM)', 2026, 536::numeric, 302::numeric, 770::numeric, 'naive', 'ward_swm'),
      ('H/E', 'Solid Waste Management (SWM)', 2026, 742::numeric, 419::numeric, 1065::numeric, 'naive', 'ward_swm'),
      ('H/W', 'Solid Waste Management (SWM)', 2026, 897::numeric, 506::numeric, 1288::numeric, 'naive', 'ward_swm'),
      ('K/E', 'Solid Waste Management (SWM)', 2026, 1204::numeric, 679::numeric, 1729::numeric, 'naive', 'ward_swm'),
      ('K/W', 'Solid Waste Management (SWM)', 2026, 2207::numeric, 1245::numeric, 3169::numeric, 'naive', 'ward_swm'),
      ('L', 'Solid Waste Management (SWM)', 2026, 1543::numeric, 871::numeric, 2215::numeric, 'naive', 'ward_swm'),
      ('M/E', 'Solid Waste Management (SWM)', 2026, 899::numeric, 507::numeric, 1291::numeric, 'naive', 'ward_swm'),
      ('M/W', 'Solid Waste Management (SWM)', 2026, 779::numeric, 440::numeric, 1118::numeric, 'naive', 'ward_swm'),
      ('N', 'Solid Waste Management (SWM)', 2026, 836::numeric, 472::numeric, 1200::numeric, 'naive', 'ward_swm'),
      ('P/N', 'Solid Waste Management (SWM)', 2026, 1495::numeric, 844::numeric, 2146::numeric, 'naive', 'ward_swm'),
      ('P/S', 'Solid Waste Management (SWM)', 2026, 1623::numeric, 916::numeric, 2330::numeric, 'naive', 'ward_swm'),
      ('R/C', 'Solid Waste Management (SWM)', 2026, 969::numeric, 547::numeric, 1391::numeric, 'naive', 'ward_swm'),
      ('R/N', 'Solid Waste Management (SWM)', 2026, 699::numeric, 394::numeric, 1004::numeric, 'naive', 'ward_swm'),
      ('R/S', 'Solid Waste Management (SWM)', 2026, 1110::numeric, 626::numeric, 1594::numeric, 'naive', 'ward_swm'),
      ('S', 'Solid Waste Management (SWM)', 2026, 3036::numeric, 1713::numeric, 4359::numeric, 'naive', 'ward_swm'),
      ('T', 'Solid Waste Management (SWM)', 2026, 405::numeric, 229::numeric, 581::numeric, 'naive', 'ward_swm'),
      ('A', 'Drainage', 2026, 256::numeric, 186::numeric, 326::numeric, 'naive', 'ward_drainage'),
      ('B', 'Drainage', 2026, 395::numeric, 287::numeric, 503::numeric, 'naive', 'ward_drainage'),
      ('C', 'Drainage', 2026, 547::numeric, 397::numeric, 697::numeric, 'naive', 'ward_drainage'),
      ('D', 'Drainage', 2026, 701::numeric, 509::numeric, 893::numeric, 'naive', 'ward_drainage'),
      ('E', 'Drainage', 2026, 43::numeric, 31::numeric, 55::numeric, 'naive', 'ward_drainage'),
      ('F/N', 'Drainage', 2026, 460::numeric, 334::numeric, 586::numeric, 'naive', 'ward_drainage'),
      ('F/S', 'Drainage', 2026, 376::numeric, 273::numeric, 479::numeric, 'naive', 'ward_drainage'),
      ('G/N', 'Drainage', 2026, 798::numeric, 580::numeric, 1016::numeric, 'naive', 'ward_drainage'),
      ('G/S', 'Drainage', 2026, 550::numeric, 399::numeric, 701::numeric, 'naive', 'ward_drainage'),
      ('H/E', 'Drainage', 2026, 688::numeric, 500::numeric, 876::numeric, 'naive', 'ward_drainage'),
      ('H/W', 'Drainage', 2026, 642::numeric, 466::numeric, 818::numeric, 'naive', 'ward_drainage'),
      ('K/E', 'Drainage', 2026, 968::numeric, 703::numeric, 1233::numeric, 'naive', 'ward_drainage'),
      ('K/W', 'Drainage', 2026, 1079::numeric, 784::numeric, 1374::numeric, 'naive', 'ward_drainage'),
      ('L', 'Drainage', 2026, 906::numeric, 658::numeric, 1154::numeric, 'naive', 'ward_drainage'),
      ('M/E', 'Drainage', 2026, 842::numeric, 611::numeric, 1073::numeric, 'naive', 'ward_drainage'),
      ('M/W', 'Drainage', 2026, 623::numeric, 452::numeric, 794::numeric, 'naive', 'ward_drainage'),
      ('N', 'Drainage', 2026, 736::numeric, 534::numeric, 938::numeric, 'naive', 'ward_drainage'),
      ('P/N', 'Drainage', 2026, 1152::numeric, 837::numeric, 1467::numeric, 'naive', 'ward_drainage'),
      ('P/S', 'Drainage', 2026, 604::numeric, 439::numeric, 769::numeric, 'naive', 'ward_drainage'),
      ('R/C', 'Drainage', 2026, 562::numeric, 408::numeric, 716::numeric, 'naive', 'ward_drainage'),
      ('R/N', 'Drainage', 2026, 339::numeric, 246::numeric, 432::numeric, 'naive', 'ward_drainage'),
      ('R/S', 'Drainage', 2026, 657::numeric, 477::numeric, 837::numeric, 'naive', 'ward_drainage'),
      ('S', 'Drainage', 2026, 912::numeric, 662::numeric, 1162::numeric, 'naive', 'ward_drainage'),
      ('T', 'Drainage', 2026, 350::numeric, 254::numeric, 446::numeric, 'naive', 'ward_drainage'),
      (null, 'Buildings', 2026, 15226::numeric, 11314::numeric, 19138::numeric, 'mean3', 'city_issue'),
      (null, 'Colony Officer', 2026, 947::numeric, 704::numeric, 1190::numeric, 'mean3', 'city_issue'),
      (null, 'Drainage', 2026, 16956::numeric, 12600::numeric, 21312::numeric, 'mean3', 'city_issue'),
      (null, 'Estate', 2026, 866::numeric, 644::numeric, 1089::numeric, 'mean3', 'city_issue'),
      (null, 'Garden', 2026, 3516::numeric, 2613::numeric, 4420::numeric, 'mean3', 'city_issue'),
      (null, 'License', 2026, 14461::numeric, 10745::numeric, 18176::numeric, 'mean3', 'city_issue'),
      (null, 'MCGM Related', 2026, 742::numeric, 551::numeric, 933::numeric, 'mean3', 'city_issue'),
      (null, 'Medical Officer Health (MOH)', 2026, 1710::numeric, 1271::numeric, 2150::numeric, 'mean3', 'city_issue'),
      (null, 'Miscellaneous issues in Civic', 2026, 2482::numeric, 1844::numeric, 3119::numeric, 'mean3', 'city_issue'),
      (null, 'Pest control', 2026, 9316::numeric, 6922::numeric, 11709::numeric, 'mean3', 'city_issue'),
      (null, 'Pollution', 2026, 912::numeric, 677::numeric, 1146::numeric, 'mean3', 'city_issue'),
      (null, 'Roads', 2026, 10567::numeric, 7852::numeric, 13282::numeric, 'mean3', 'city_issue'),
      (null, 'School', 2026, 73::numeric, 54::numeric, 92::numeric, 'mean3', 'city_issue'),
      (null, 'Shop and Establishment', 2026, 661::numeric, 491::numeric, 831::numeric, 'mean3', 'city_issue'),
      (null, 'Solid Waste Management (SWM)', 2026, 25886::numeric, 19235::numeric, 32537::numeric, 'mean3', 'city_issue'),
      (null, 'Storm Water Drainage', 2026, 2539::numeric, 1887::numeric, 3191::numeric, 'mean3', 'city_issue'),
      (null, 'Toilet', 2026, 576::numeric, 428::numeric, 724::numeric, 'mean3', 'city_issue'),
      (null, 'Water Supply', 2026, 14484::numeric, 10763::numeric, 18205::numeric, 'mean3', 'city_issue'),
      (null, null, 2026, 125270::numeric, 112504::numeric, 138037::numeric, 'trend', 'city_total')
    ) as v(code, category, year, value, lower, upper, method, family)
    left join city_zones z on z.organization_id = p_org and z.code = v.code;

  return jsonb_build_object(
    'models',    (select count(*) from ml_models where organization_id = p_org),
    'clusters',  (select count(*) from ml_ward_clusters where organization_id = p_org),
    'forecasts', (select count(*) from ml_forecasts where organization_id = p_org));
end $fn$;

revoke all on function app.load_mumbai_models(uuid) from public, anon, authenticated;
