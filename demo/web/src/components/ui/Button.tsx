import type { ButtonHTMLAttributes } from "react";
import { Loader2 } from "lucide-react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  loading?: boolean;
  variant?: "primary" | "secondary";
}

export function Button({
  loading = false,
  variant = "primary",
  className = "",
  children,
  disabled,
  ...rest
}: ButtonProps) {
  const base =
    "inline-flex items-center gap-2 rounded-lg px-4 py-2.5 font-mono text-sm font-semibold transition-all duration-150 disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:translate-y-0 disabled:hover:shadow-none";

  const styles =
    variant === "primary"
      ? "bg-amber-500 text-zinc-950 shadow-[3px_3px_0_0_rgba(0,0,0,0.15)] hover:-translate-y-0.5 hover:bg-amber-400 hover:shadow-[4px_4px_0_0_rgba(0,0,0,0.2)] active:translate-y-0 active:shadow-[2px_2px_0_0_rgba(0,0,0,0.15)] dark:shadow-[3px_3px_0_0_rgba(0,0,0,0.5)] dark:hover:shadow-[4px_4px_0_0_rgba(0,0,0,0.6)] dark:active:shadow-[2px_2px_0_0_rgba(0,0,0,0.5)]"
      : "bg-zinc-900/5 text-zinc-800 hover:bg-zinc-900/10 dark:bg-white/5 dark:text-zinc-100 dark:hover:bg-white/10";

  return (
    <button className={`${base} ${styles} ${className}`} disabled={disabled || loading} {...rest}>
      {loading && <Loader2 className="h-4 w-4 animate-spin" />}
      {children}
    </button>
  );
}
