import { useRef, useState } from "react";
import { FileText } from "lucide-react";
import { TerminalWindow } from "../../../components/ui/TerminalWindow";
import { Button } from "../../../components/ui/Button";
import { Label, TextInput } from "../../../components/ui/Field";
import { StatLine } from "../../../components/ui/StatLine";
import { ResultPanel } from "../../../components/ui/ResultPanel";
import { runFileRoundTrip, type FileReport } from "../../../lib/api";
import { formatBytes } from "../../../lib/format";

const SAMPLE_SIZE_BYTES = 8 * 1024;
const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;

function makeSampleFile(): File {
  const chunk = "Temant encryption-manager sample file. ";
  const text = chunk.repeat(Math.ceil(SAMPLE_SIZE_BYTES / chunk.length));
  return new File([text], "notes.txt", { type: "text/plain" });
}

export function FilesSection() {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<FileReport | null>(null);
  const [reportNonce, setReportNonce] = useState(0);
  const [sizeError, setSizeError] = useState<string | null>(null);

  const pickFile = (picked: File | null) => {
    setReport(null);
    if (picked && picked.size > MAX_UPLOAD_BYTES) {
      setSizeError(
        `That file is ${formatBytes(picked.size)}; encryptFile() loads it fully into memory, so this demo caps it at ${formatBytes(MAX_UPLOAD_BYTES)}. Try the streamed file encryption tab instead.`,
      );
      setFile(null);
      return;
    }
    setSizeError(null);
    setFile(picked);
  };

  const useSample = () => {
    if (fileInputRef.current) fileInputRef.current.value = "";
    pickFile(makeSampleFile());
  };

  const run = async () => {
    if (!file) return;
    setLoading(true);
    setReport(null);
    const res = await runFileRoundTrip(file, password);
    setReport(res);
    setReportNonce(Date.now());
    setLoading(false);
  };

  return (
    <TerminalWindow label="encrypt-file.sh" meta="v1: payload">
      <div className="mb-5 flex items-center gap-2.5">
        <FileText className="h-4 w-4 text-amber-500" />
        <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-100">File encryption</span>
      </div>

      <p className="mb-4 text-sm leading-relaxed text-zinc-500 dark:text-zinc-400">
        <code className="rounded bg-zinc-900/5 px-1 py-0.5 font-mono text-xs dark:bg-white/10">encryptFile()</code>{" "}
        and{" "}
        <code className="rounded bg-zinc-900/5 px-1 py-0.5 font-mono text-xs dark:bg-white/10">decryptFile()</code>{" "}
        read the whole file into memory and produce the same printable{" "}
        <code className="rounded bg-zinc-900/5 px-1 py-0.5 font-mono text-xs dark:bg-white/10">v1:</code> payload as{" "}
        <code className="rounded bg-zinc-900/5 px-1 py-0.5 font-mono text-xs dark:bg-white/10">encryptString()</code>{" "}
        — good for small files; for large files, use streamed file encryption instead.
      </p>

      <div className="space-y-3.5">
        <div>
          <Label>file</Label>
          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
              className="block w-full flex-1 font-mono text-xs text-zinc-500 file:mr-3 file:rounded-lg file:border-0 file:bg-zinc-900/5 file:px-3 file:py-2 file:font-mono file:text-xs file:text-zinc-700 hover:file:bg-zinc-900/10 dark:text-zinc-400 dark:file:bg-white/5 dark:file:text-zinc-200 dark:hover:file:bg-white/10"
            />
            <Button type="button" variant="secondary" onClick={useSample}>
              Use 8 KB sample
            </Button>
          </div>
          {file && (
            <div className="mt-1.5 font-mono text-xs text-zinc-500 dark:text-zinc-500">
              {file.name} &middot; {formatBytes(file.size)}
            </div>
          )}
          {sizeError && <div className="mt-1.5 font-mono text-xs text-red-500">{sizeError}</div>}
        </div>

        <div>
          <Label>password (optional)</Label>
          <TextInput value={password} onChange={(e) => setPassword(e.target.value)} placeholder="App-secret mode" />
        </div>

        <Button type="button" loading={loading} disabled={!file} onClick={run}>
          Run file round-trip
        </Button>

        {report && (
          <div className="mt-1 animate-rise overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950 px-3.5 py-3 font-mono text-xs">
            {report.ok ? (
              <div className="space-y-1">
                <StatLine label="original" value={formatBytes(report.originalBytes ?? 0)} tone="ok" />
                <StatLine label="payload" value={formatBytes(report.payloadBytes ?? 0)} tone="ok" />
                <StatLine
                  label="round-trip integrity"
                  value={report.integrityMatch ? "match" : "MISMATCH"}
                  tone={report.integrityMatch ? "ok" : "error"}
                />
                <StatLine
                  label="tamper detection"
                  value={report.tamperDetected ? "rejected as expected" : "NOT DETECTED"}
                  tone={report.tamperDetected ? "ok" : "error"}
                />
                <StatLine label="timing" value={`encrypt ${report.encryptMs}ms, decrypt ${report.decryptMs}ms`} tone="ok" />
              </div>
            ) : (
              <span className="text-red-400">! {report.error}</span>
            )}
          </div>
        )}

        {report?.ok && report.payload && <ResultPanel tone="ok" text={report.payload} nonce={reportNonce} />}
      </div>
    </TerminalWindow>
  );
}
