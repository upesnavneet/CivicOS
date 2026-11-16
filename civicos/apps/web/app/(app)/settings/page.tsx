import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Card } from "@/components/ui";
import { requireSession } from "@/lib/auth";
import { canAccess, ROLE_LABEL, type Role } from "@/lib/permissions";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = { title: "Settings" };

const LIMIT_LABEL: Record<string, string> = {
  max_users: "Users",
  max_documents: "Documents",
  ai_queries_per_month: "AI queries per month",
};

export default async function SettingsPage() {
  const session = await requireSession();
  if (!canAccess(session.role, "/settings")) redirect("/dashboard");

  const supabase = await createClient();
  const [{ data: org }, { data: members }, { data: departments }] = await Promise.all([
    supabase.from("organizations").select("name, slug, status, plan_code, created_at, plans(name, limits)").eq("id", session.orgId).maybeSingle(),
    supabase.from("users").select("id, full_name, email, role, is_active").order("created_at"),
    supabase.from("departments").select("id, name, code").order("name"),
  ]);

  const plan = (Array.isArray(org?.plans) ? org?.plans[0] : org?.plans) as { name: string; limits: Record<string, unknown> } | null | undefined;

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>

      <Card className="p-5">
        <h2 className="text-sm font-medium">Organization</h2>
        <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-3">
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted">Name</dt>
            <dd className="mt-1">{org?.name}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted">Workspace ID</dt>
            <dd className="mt-1 font-mono text-xs">{org?.slug}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted">Status</dt>
            <dd className="mt-1 capitalize">{org?.status}</dd>
          </div>
        </dl>
      </Card>

      <Card className="p-5">
        <h2 className="text-sm font-medium">Plan: {plan?.name ?? org?.plan_code}</h2>
        <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-3">
          {Object.entries(LIMIT_LABEL).map(([key, label]) => (
            <div key={key}>
              <dt className="text-xs uppercase tracking-wide text-muted">{label}</dt>
              <dd className="mt-1 tabular-nums">{plan?.limits?.[key] == null ? "Unlimited" : String(plan.limits[key])}</dd>
            </div>
          ))}
        </dl>
      </Card>

      <Card className="overflow-hidden">
        <h2 className="px-5 pt-5 text-sm font-medium">Members ({members?.length ?? 0})</h2>
        <table className="mt-3 w-full text-left text-sm">
          <thead className="border-y border-line text-xs uppercase tracking-wide text-muted">
            <tr>
              <th className="px-5 py-2 font-medium">Name</th>
              <th className="px-5 py-2 font-medium">Email</th>
              <th className="px-5 py-2 font-medium">Role</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {(members ?? []).map((m) => (
              <tr key={m.id}>
                <td className="px-5 py-3">{m.full_name}</td>
                <td className="px-5 py-3 text-muted">{m.email}</td>
                <td className="px-5 py-3">{ROLE_LABEL[m.role as Role] ?? m.role}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card className="p-5">
        <h2 className="text-sm font-medium">Departments ({departments?.length ?? 0})</h2>
        <ul className="mt-4 grid gap-2 sm:grid-cols-2">
          {(departments ?? []).map((d) => (
            <li key={d.id} className="flex items-center justify-between rounded-lg border border-line px-3 py-2 text-sm">
              {d.name}
              <span className="font-mono text-xs text-faint">{d.code}</span>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
