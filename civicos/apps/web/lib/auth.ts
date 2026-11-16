import "server-only";
import { redirect } from "next/navigation";
import { createClient } from "./supabase/server";
import type { Role } from "./permissions";

export type Session = {
  userId: string;
  email: string;
  fullName: string;
  role: Role;
  orgId: string;
  departmentId: string | null;
};

/**
 * Returns the signed-in user with tenant claims, or redirects to /login.
 * Claims come from the JWT app_metadata, which a database trigger keeps in sync with public.users.
 */
export async function requireSession(): Promise<Session> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const meta = user.app_metadata ?? {};
  if (!meta.org_id || !meta.role) redirect("/login?error=" + encodeURIComponent("This account is not linked to an organization."));

  return {
    userId: user.id,
    email: user.email ?? "",
    fullName: (user.user_metadata?.full_name as string) ?? user.email ?? "",
    role: meta.role as Role,
    orgId: meta.org_id as string,
    departmentId: (meta.department_id as string) ?? null,
  };
}
