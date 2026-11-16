-- CivicOS 0001: extensions
-- Supabase keeps extensions in the "extensions" schema, which is on the search_path.
create extension if not exists pgcrypto with schema extensions;
create extension if not exists postgis  with schema extensions;
create extension if not exists vector   with schema extensions;
