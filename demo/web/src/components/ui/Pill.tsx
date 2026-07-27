import type { ReactNode } from "react";

export function Pill({ children, tone }: { children: ReactNode; tone?: "ok" | "bad" }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-zinc-200/70 bg-white/70 px-2.5 py-1 text-xs text-zinc-600 backdrop-blur-sm dark:border-white/10 dark:bg-white/5 dark:text-zinc-400">
      {tone && (
        <span
          className={`h-1.5 w-1.5 rounded-full ${tone === "ok" ? "bg-emerald-500" : "bg-red-500"}`}
        />
      )}
      {children}
    </span>
  );
}
