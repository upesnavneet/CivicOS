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
