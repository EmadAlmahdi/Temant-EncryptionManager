export function StatLine({ label, value, tone }: { label: string; value: string; tone: "ok" | "error" }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className="w-40 shrink-0 text-zinc-500">{label}</span>
      <span className={tone === "ok" ? "text-emerald-400" : "text-red-400"}>{value}</span>
    </div>
  );
}
