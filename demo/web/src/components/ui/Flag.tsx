import type { ReactNode } from "react";

/** A status badge styled like a CLI flag (`--openssl=loaded`) instead of a generic pill. */
export function Flag({ children, tone }: { children: ReactNode; tone?: "ok" | "bad" }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded border border-zinc-200 bg-zinc-50 px-2 py-1 font-mono text-[11px] text-zinc-600 dark:border-white/10 dark:bg-white/5 dark:text-zinc-400">
      {tone && <span className={`h-1.5 w-1.5 rounded-full ${tone === "ok" ? "bg-emerald-500" : "bg-red-500"}`} />}
      {children}
    </span>
  );
}
