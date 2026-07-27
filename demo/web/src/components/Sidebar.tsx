import { Terminal } from "lucide-react";
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
    <aside className="flex w-72 shrink-0 flex-col border-r border-zinc-200 bg-white dark:border-white/10 dark:bg-zinc-950">
      <div className="border-b border-zinc-200 px-5 py-5 dark:border-white/10">
        <div className="flex items-center gap-2 font-mono text-sm text-zinc-900 dark:text-zinc-100">
          <Terminal className="h-4 w-4 text-amber-500" />
          <span className="font-semibold">temant</span>
          <span className="text-zinc-400 dark:text-zinc-600">/packages</span>
        </div>
        <div className="mt-1 font-mono text-[11px] text-zinc-400 dark:text-zinc-600">local demo &middot; v1</div>
      </div>

      <nav className="flex-1 space-y-0.5 px-3 py-4">
        {packages.map((pkg) => {
          const Icon = pkg.icon;
          const active = pkg.id === activeId;
          const slug = pkg.name.toLowerCase().replace(/\s+/g, "-");

          return (
            <button
              key={pkg.id}
              type="button"
              onClick={() => onNavigate(pkg.id)}
              className={`group flex w-full items-center gap-2.5 rounded-md px-3 py-2.5 text-left font-mono text-[13px] transition-colors ${
                active
                  ? "bg-amber-500/10 text-amber-700 dark:text-amber-400"
                  : "text-zinc-600 hover:bg-zinc-900/5 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-white/5 dark:hover:text-white"
              }`}
            >
              <Icon
                className={`h-3.5 w-3.5 shrink-0 ${active ? "text-amber-500" : "text-zinc-400 group-hover:text-zinc-600 dark:group-hover:text-zinc-300"}`}
              />
              <span className="truncate">{slug}</span>
              {active && <span className="ml-auto h-3.5 w-1.5 shrink-0 animate-caret bg-amber-500" />}
            </button>
          );
        })}
      </nav>

      <div className="flex items-center justify-between border-t border-zinc-200 px-5 py-4 dark:border-white/10">
        <span className="font-mono text-[11px] text-zinc-400 dark:text-zinc-600">status: ready</span>
        <ThemeToggle />
      </div>
    </aside>
  );
}
