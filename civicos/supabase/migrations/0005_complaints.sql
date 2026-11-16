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
