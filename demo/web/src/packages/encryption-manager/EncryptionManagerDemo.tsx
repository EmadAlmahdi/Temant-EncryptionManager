import { useEffect, useState } from "react";
import { Flag } from "../../components/ui/Flag";
import { SectionTabs } from "../../components/ui/SectionTabs";
import { fetchMeta, type MetaResponse } from "../../lib/api";
import { StringCipherSection } from "./sections/StringCipherSection";
import { FilesSection } from "./sections/FilesSection";
import { StreamedFilesSection } from "./sections/StreamedFilesSection";
import { KeyRotationSection } from "./sections/KeyRotationSection";

type Section = "cipher" | "files" | "streaming" | "rotation";

const sectionTabs = [
  { id: "cipher", label: "encrypt & decrypt" },
  { id: "files", label: "files" },
  { id: "streaming", label: "streamed files" },
  { id: "rotation", label: "key rotation" },
];

export function EncryptionManagerDemo() {
  const [meta, setMeta] = useState<MetaResponse | null>(null);
  const [section, setSection] = useState<Section>("cipher");

  useEffect(() => {
    fetchMeta()
      .then(setMeta)
      .catch(() => setMeta(null));
  }, []);

  return (
    <div className="mx-auto max-w-4xl px-6 py-14 sm:py-20">
      <header className="mb-10 animate-fade-in">
        <div className="mb-3 font-mono text-xs text-amber-600 dark:text-amber-400">
          <span className="text-zinc-400 dark:text-zinc-600">// </span>
          encryption-manager
        </div>
        <h1 className="text-3xl font-bold tracking-tight text-zinc-900 sm:text-4xl dark:text-white">
          Authenticated encryption with{" "}
          <span className="rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-amber-700 dark:text-amber-400">
            AES-GCM
          </span>
          <span className="ml-1 inline-block h-[0.85em] w-[3px] translate-y-1 animate-caret bg-amber-500 align-middle" />
        </h1>
        <p className="mt-3 max-w-xl text-sm leading-relaxed text-zinc-500 sm:text-base dark:text-zinc-400">
          Strings, whole files, and constant-memory streamed files, plus key rotation with a
          retired-key keyring — all running against the real PHP package, not a JS
          reimplementation of it.
        </p>

        {meta && (
          <div className="mt-5 flex flex-wrap gap-2">
            <Flag tone="ok">--php={meta.phpVersion}</Flag>
            <Flag tone={meta.opensslLoaded ? "ok" : "bad"}>--openssl={meta.opensslLoaded ? "loaded" : "missing"}</Flag>
            <Flag>--session-key={meta.keyFingerprint}</Flag>
          </div>
        )}
      </header>

      <SectionTabs tabs={sectionTabs} activeId={section} onChange={(id) => setSection(id as Section)} />

      <div className="animate-fade-in">
        {section === "cipher" && <StringCipherSection />}
        {section === "files" && <FilesSection />}
        {section === "streaming" && <StreamedFilesSection />}
        {section === "rotation" && <KeyRotationSection meta={meta} onMetaChange={setMeta} />}
      </div>
    </div>
  );
}
