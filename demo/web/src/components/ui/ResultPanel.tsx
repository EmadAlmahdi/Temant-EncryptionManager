import { useState } from "react";
import { AlertCircle, Check, CheckCircle2, Copy } from "lucide-react";

export function ResultPanel({ tone, text }: { tone: "ok" | "error"; text: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  const toneClasses =
    tone === "ok"
      ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-300"
      : "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300";

  return (
    <div
      className={`mt-3 flex animate-rise items-start gap-2.5 rounded-xl border px-3.5 py-3 font-mono text-sm ${toneClasses}`}
    >
      {tone === "ok" ? (
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
      ) : (
        <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
      )}
      <span className="min-w-0 flex-1 break-all">{text}</span>
      {tone === "ok" && (
        <button
          type="button"
          onClick={copy}
          className="shrink-0 rounded-md p-1 transition hover:bg-black/5 dark:hover:bg-white/10"
          aria-label="Copy to clipboard"
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
      )}
    </div>
  );
}
