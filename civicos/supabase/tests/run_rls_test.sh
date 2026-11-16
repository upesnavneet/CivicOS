#!/usr/bin/env bash
# Runs the migrations and the tenant-isolation test.
#   Plain Postgres (CI, no PostGIS):  ./run_rls_test.sh shim
#   Supabase local (supabase start):  DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:54322/postgres ./run_rls_test.sh
set -euo pipefail
cd "$(dirname "$0")"
DB="${DATABASE_URL:?set DATABASE_URL}"
P=(psql "$DB" -v ON_ERROR_STOP=1 -q)

if [[ "${1:-}" == "shim" ]]; then
  "${P[@]}" -f shim_vanilla_postgres.sql
  for f in $(ls ../migrations/*.sql | grep -v 0001_); do
    # geometry(...) columns become text and GiST indexes are dropped: test-only rewrite
    sed -E -e 's/geometry\([^)]*\)/text/g' -e '/using gist/d' "$f" | "${P[@]}"
  done
fi
"${P[@]}" -f rls_isolation.sql
