import type { CSSProperties, ReactNode } from "react";

export function Card({
  children,
  className = "",
  style,
}: {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div
      style={style}
      className={`rounded-2xl border border-zinc-200/70 bg-white/80 shadow-xl shadow-zinc-900/5 backdrop-blur-sm dark:border-white/10 dark:bg-zinc-900/60 dark:shadow-black/20 ${className}`}
    >
      {children}
    </div>
  );
}
