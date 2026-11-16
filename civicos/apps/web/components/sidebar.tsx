"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  BarChart3, Bot, Droplets, LayoutDashboard, Lightbulb, Map, MessageSquareWarning, Settings, TrafficCone, Trash2,
  type LucideIcon,
} from "lucide-react";
import { CURRENT_PHASE, type NavItem } from "@/lib/permissions";

const ICONS: Record<NavItem["icon"], LucideIcon> = {
  dashboard: LayoutDashboard,
  map: Map,
  water: Droplets,
  waste: Trash2,
  traffic: TrafficCone,
  complaints: MessageSquareWarning,
  assistant: Bot,
  insights: Lightbulb,
  analytics: BarChart3,
  settings: Settings,
};

export function SidebarNav({ items }: { items: NavItem[] }) {
  const pathname = usePathname();

  return (
    <nav aria-label="Main" className="flex flex-col gap-0.5">
      {items.map((item) => {
        const Icon = ICONS[item.icon];
        const active = pathname === item.href || pathname.startsWith(item.href + "/");
        const base = "flex items-center gap-3 rounded-lg px-3 py-2 text-sm";

        if (item.phase > CURRENT_PHASE) {
          return (
            <span key={item.href} aria-disabled="true" className={`${base} cursor-not-allowed text-faint`} title={`Arrives in phase ${item.phase}`}>
              <Icon className="size-4 shrink-0" aria-hidden="true" />
              <span className="flex-1">{item.label}</span>
              <span className="rounded border border-line px-1.5 py-px text-[10px] uppercase tracking-wide">P{item.phase}</span>
            </span>
          );
        }
        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={active ? "page" : undefined}
            className={`${base} ${active ? "bg-raised font-medium text-ink" : "text-muted hover:bg-raised/60 hover:text-ink"}`}
          >
            <Icon className={`size-4 shrink-0 ${active ? "text-accent" : ""}`} aria-hidden="true" />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
