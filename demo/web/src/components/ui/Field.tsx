import type { InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from "react";

export function Label({ children }: { children: ReactNode }) {
  return (
    <label className="mb-2 flex items-center gap-1.5 font-mono text-xs text-zinc-500 dark:text-zinc-500">
      <span className="text-amber-500 dark:text-amber-400">//</span>
      {children}
    </label>
  );
}

const fieldClasses =
  "w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3.5 py-2.5 font-mono text-sm text-zinc-900 outline-none transition-all placeholder:text-zinc-400 focus:border-amber-500 focus:bg-white focus:ring-2 focus:ring-amber-500/20 dark:border-white/10 dark:bg-black/30 dark:text-zinc-100 dark:placeholder:text-zinc-600 dark:focus:border-amber-400 dark:focus:bg-black/50 dark:focus:ring-amber-400/10";

export function TextArea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const { className = "", ...rest } = props;
  return <textarea {...rest} className={`${fieldClasses} min-h-24 resize-y ${className}`} />;
}

export function TextInput(props: InputHTMLAttributes<HTMLInputElement>) {
  const { className = "", ...rest } = props;
  return <input {...rest} className={`${fieldClasses} ${className}`} />;
}
