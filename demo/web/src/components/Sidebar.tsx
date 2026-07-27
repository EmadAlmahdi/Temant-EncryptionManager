import { ShieldCheck } from "lucide-react";
import type { PackageDemo } from "../packages/registry";
import { ThemeToggle } from "./ThemeToggle";

export function Sidebar({
  packages,
  activeId,
  onNavigate,
}: {
  packages: PackageDemo[];
  activeId: string;
  onNavigate: (id: string) => void;
}) {
  return (
    <aside className="flex w-72 shrink-0 flex-col border-r border-zinc-200/70 bg-white/70 backdrop-blur-xl dark:border-white/5 dark:bg-zinc-950/70">
      <div className="flex items-center gap-3 px-6 py-6">
        <div className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 via-violet-500 to-fuchsia-500 text-white shadow-lg shadow-violet-500/30">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <div className="text-base font-bold tracking-tight text-zinc-900 dark:text-white">Temant</div>
          <div className="text-xs text-zinc-500 dark:text-zinc-400">Package demos</div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-4">
        {packages.map((pkg) => {
          const Icon = pkg.icon;
          const active = pkg.id === activeId;

          return (
            <button
              key={pkg.id}
              type="button"
              onClick={() => onNavigate(pkg.id)}
              className={`group relative flex w-full items-center gap-3 rounded-xl px-3.5 py-3 text-left text-sm transition-all ${
                active
                  ? "bg-gradient-to-r from-indigo-500/10 to-violet-500/5 text-indigo-700 dark:text-indigo-300"
                  : "text-zinc-600 hover:bg-zinc-900/5 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-white/5 dark:hover:text-white"
              }`}
            >
              {active && (
                <span className="absolute top-1/2 left-0 h-5 w-1 -translate-y-1/2 rounded-full bg-gradient-to-b from-indigo-500 to-violet-500" />
              )}
              <Icon
                className={`h-4 w-4 shrink-0 transition-colors ${
                  active ? "text-indigo-500" : "text-zinc-400 group-hover:text-zinc-600 dark:group-hover:text-zinc-300"
                }`}
              />
              <div className="min-w-0">
                <div className="truncate font-semibold">{pkg.name}</div>
                <div
                  className={`truncate text-xs ${active ? "text-indigo-500/70 dark:text-indigo-300/60" : "text-zinc-400 dark:text-zinc-500"}`}
                >
                  {pkg.tagline}
                </div>
              </div>
            </button>
          );
        })}
      </nav>

      <div className="flex items-center justify-between border-t border-zinc-200/70 px-6 py-4 dark:border-white/5">
        <span className="text-xs text-zinc-400 dark:text-zinc-500">Local demo</span>
        <ThemeToggle />
      </div>
    </aside>
  );
}
