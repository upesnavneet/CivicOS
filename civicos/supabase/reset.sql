-- Removes everything CivicOS created, so all_migrations.sql can be run again from scratch.
-- Use this only if you ran an earlier version of the migrations. It deletes all CivicOS data
-- in this project. Auth users are kept; delete them under Authentication -> Users if you want a clean start.
drop function if exists public.dashboard_data(date, date, uuid, uuid, uuid, text);
drop function if exists public.dashboard_data(int, uuid, text);
drop function if exists public.map_data(date, date, text, uuid);
drop function if exists public.map_data(int, text);
drop function if exists public.ward_stats(int, text);
drop function if exists public.ml_data(uuid, text);
drop function if exists public.register_organization(uuid, text, text, text);
drop function if exists public.register_organization(uuid, text, text, text, text);
drop table if exists
  public.ml_forecasts, public.ml_ward_clusters, public.ml_models,
  public.civic_indicators, public.data_sources, public.health_index_config, public.health_index_snapshots,
  public.environment_readings, public.traffic_incidents, public.traffic_readings,
  public.waste_readings, public.waste_bins, public.water_readings, public.water_sensors,
  public.complaints, public.complaint_categories, public.infrastructure_assets,
  public.city_zones, public.cities, public.audit_logs, public.api_keys, public.usage_records,
  public.invitations, public.subscriptions, public.users, public.departments, public.organizations,
  public.role_permissions, public.permissions, public.roles, public.plans
  cascade;
drop schema if exists app cascade;
