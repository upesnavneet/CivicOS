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
