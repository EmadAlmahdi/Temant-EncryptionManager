import type { CSSProperties, ReactNode } from "react";

export interface TerminalTab {
  id: string;
  label: string;
}

interface TerminalWindowProps {
  /** Static title bar text. Ignored if `tabs` is given. */
  label?: string;
  /** Makes the title bar a set of clickable tabs (e.g. encrypt.sh / decrypt.sh) instead of a static label. */
  tabs?: TerminalTab[];
  activeTab?: string;
  onTabChange?: (id: string) => void;
  meta?: string;
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
}

export function TerminalWindow({
  label,
  tabs,
  activeTab,
  onTabChange,
  meta,
  children,
  className = "",
  style,
}: TerminalWindowProps) {
  return (
    <div
      style={style}
      className={`overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-[4px_4px_0_0_rgba(0,0,0,0.06)] dark:border-white/10 dark:bg-zinc-950 dark:shadow-[4px_4px_0_0_rgba(0,0,0,0.4)] ${className}`}
    >
      <div className="flex items-center justify-between border-b border-zinc-200 bg-zinc-50 px-4 dark:border-white/10 dark:bg-white/[0.03]">
        <div className="flex items-center gap-3">
          <div className="flex shrink-0 gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-red-400/70" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" />
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/70" />
          </div>

          {tabs ? (
            <div className="flex items-stretch">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => onTabChange?.(tab.id)}
                  className={`border-b-2 px-3 py-2.5 font-mono text-xs transition-colors ${
                    tab.id === activeTab
                      ? "border-amber-500 text-amber-700 dark:text-amber-400"
                      : "border-transparent text-zinc-400 hover:text-zinc-600 dark:text-zinc-600 dark:hover:text-zinc-400"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          ) : (
            <span className="py-2.5 font-mono text-xs text-zinc-500 dark:text-zinc-400">{label}</span>
          )}
        </div>
        {meta && (
          <span className="shrink-0 font-mono text-[10px] tracking-wider text-zinc-400 uppercase dark:text-zinc-600">
            {meta}
          </span>
        )}
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}
