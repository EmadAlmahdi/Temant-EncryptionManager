import type { InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from "react";

export function Label({ children }: { children: ReactNode }) {
  return (
    <label className="mb-1.5 block text-xs font-semibold tracking-wide text-zinc-500 uppercase dark:text-zinc-400">
      {children}
    </label>
  );
}

const fieldClasses =
  "w-full rounded-xl border border-zinc-200 bg-zinc-50/80 px-3.5 py-2.5 font-mono text-sm text-zinc-900 outline-none transition-all placeholder:text-zinc-400 focus:border-indigo-500 focus:bg-white focus:ring-4 focus:ring-indigo-500/10 dark:border-white/10 dark:bg-white/5 dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:border-indigo-400 dark:focus:bg-zinc-900 dark:focus:ring-indigo-400/10";

export function TextArea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const { className = "", ...rest } = props;
  return <textarea {...rest} className={`${fieldClasses} min-h-24 resize-y ${className}`} />;
}

export function TextInput(props: InputHTMLAttributes<HTMLInputElement>) {
  const { className = "", ...rest } = props;
  return <input {...rest} className={`${fieldClasses} ${className}`} />;
}
