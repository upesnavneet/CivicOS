export function Logo({ size = 28 }: { size?: number }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
        <rect width="32" height="32" rx="8" className="fill-accent" />
        <path d="M8 23V13l4-3v13M14 23V9l4 3v11M20 23v-8l4-2v10" className="stroke-accent-ink" strokeWidth="2" fill="none" strokeLinejoin="round" />
      </svg>
      <span className="text-[17px] font-semibold tracking-tight text-ink">
        Civic<span className="text-accent">OS</span>
      </span>
    </span>
  );
}
