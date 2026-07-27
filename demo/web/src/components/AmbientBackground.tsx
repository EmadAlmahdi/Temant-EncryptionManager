/**
 * A faint technical dot grid plus a single restrained glow, instead of the generic soft
 * multi-color blur blobs — meant to read as "engineered" rather than "marketing site".
 * Purely decorative, non-interactive, and static (no motion).
 */
export function AmbientBackground() {
  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <div className="bg-grid absolute inset-0 text-zinc-900/[0.05] dark:text-white/[0.06]" />
      <div className="absolute -top-40 left-1/2 h-[420px] w-[820px] -translate-x-1/2 rounded-full bg-amber-400/10 blur-[140px] dark:bg-amber-500/10" />
    </div>
  );
}
