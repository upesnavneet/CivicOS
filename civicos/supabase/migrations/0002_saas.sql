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
