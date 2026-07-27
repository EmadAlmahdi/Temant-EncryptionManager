export interface SectionTab {
  id: string;
  label: string;
}

export function SectionTabs({
  tabs,
  activeId,
  onChange,
}: {
  tabs: SectionTab[];
  activeId: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="mb-6 flex flex-wrap gap-1 rounded-lg border border-zinc-200 bg-zinc-50 p-1 font-mono text-xs dark:border-white/10 dark:bg-white/[0.03]">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={`rounded-md px-3 py-1.5 transition-colors ${
            tab.id === activeId
              ? "bg-white text-amber-700 shadow-sm dark:bg-zinc-900 dark:text-amber-400"
              : "text-zinc-500 hover:text-zinc-800 dark:text-zinc-500 dark:hover:text-zinc-300"
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
