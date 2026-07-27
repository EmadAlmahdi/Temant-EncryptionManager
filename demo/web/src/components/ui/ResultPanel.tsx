import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { useScramble } from "../../lib/useScramble";

export function ResultPanel({ tone, text, nonce }: { tone: "ok" | "error"; text: string; nonce: number }) {
  const scrambled = useScramble(text, nonce);
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  const textColor = tone === "ok" ? "text-emerald-400" : "text-red-400";

  return (
    <div className="mt-3 animate-rise overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950">
      <div className="flex items-start gap-2.5 px-3.5 py-3">
        <span className={`shrink-0 font-mono text-sm select-none ${textColor}`}>{tone === "ok" ? ">" : "!"}</span>
        <span className={`min-w-0 flex-1 font-mono text-sm break-all ${textColor}`}>{scrambled}</span>
        {tone === "ok" && (
          <button
            type="button"
            onClick={copy}
            className="shrink-0 rounded p-1 text-zinc-500 transition hover:bg-white/10 hover:text-zinc-300"
            aria-label="Copy to clipboard"
          >
            {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          </button>
        )}
      </div>
    </div>
  );
}
