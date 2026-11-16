import { LogOut } from "lucide-react";
import { logout } from "@/app/auth/actions";
import { Logo } from "@/components/logo";
import { SidebarNav } from "@/components/sidebar";
import { Badge } from "@/components/ui";
import { requireSession } from "@/lib/auth";
import { navFor, ROLE_LABEL } from "@/lib/permissions";
import { createClient } from "@/lib/supabase/server";

export default async function AppLayout({ children }: LayoutProps<"/">) {
  const session = await requireSession();
  const supabase = await createClient();
  const { data: org } = await supabase.from("organizations").select("name, plan_code").eq("id", session.orgId).maybeSingle();

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-panel px-3 py-5 md:flex">
        <div className="px-3 pb-6">
          <Logo />
        </div>
        <SidebarNav items={navFor(session.role)} />

        <div className="mt-auto border-t border-line px-3 pt-4">
          <p className="truncate text-sm font-medium">{session.fullName}</p>
          <p className="truncate text-xs text-muted">{ROLE_LABEL[session.role]}</p>
          <form action={logout} className="mt-3">
            <button type="submit" className="inline-flex items-center gap-2 text-xs text-muted hover:text-ink">
              <LogOut className="size-3.5" aria-hidden="true" />
              Sign out
            </button>
          </form>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center justify-between border-b border-line px-6">
          <div className="flex min-w-0 items-center gap-3">
            <span className="truncate text-sm font-medium">{org?.name ?? "Organization"}</span>
            <Badge tone="accent">{org?.plan_code ?? "free"}</Badge>
          </div>
          <Badge>Published data only</Badge>
        </header>
        <main className="flex-1 px-6 py-8">{children}</main>
      </div>
    </div>
  );
}
