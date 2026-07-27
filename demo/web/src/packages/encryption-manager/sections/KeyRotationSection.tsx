import { useState } from "react";
import { KeyRound } from "lucide-react";
import { TerminalWindow } from "../../../components/ui/TerminalWindow";
import { Button } from "../../../components/ui/Button";
import { Flag } from "../../../components/ui/Flag";
import { encryptString, decryptString, rotateSecret, type MetaResponse } from "../../../lib/api";

interface LogLine {
  tone: "ok" | "error" | "info";
  text: string;
}

const SAMPLE_PLAINTEXT = "archived record #1234";

export function KeyRotationSection({
  meta,
  onMetaChange,
}: {
  meta: MetaResponse | null;
  onMetaChange: (meta: MetaResponse) => void;
}) {
  const [log, setLog] = useState<LogLine[]>([]);
  const [oldPayload, setOldPayload] = useState<string | null>(null);
  const [encryptedUnder, setEncryptedUnder] = useState<string | null>(null);
  const [retireCurrent, setRetireCurrent] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);

  const append = (line: LogLine) => setLog((prev) => [...prev, line]);

  const step1Encrypt = async () => {
    setBusy("encrypt");
    const res = await encryptString(SAMPLE_PLAINTEXT, "");
    if (res.ok && res.result) {
      setOldPayload(res.result);
      setEncryptedUnder(meta?.keyFingerprint ?? "?");
      append({
        tone: "ok",
        text: `$ encrypt "${SAMPLE_PLAINTEXT}" --key=#${meta?.keyFingerprint ?? "?"} → ok`,
      });
    } else {
      append({ tone: "error", text: `$ encrypt → ${res.error ?? "failed"}` });
    }
    setBusy(null);
  };

  const step2Rotate = async () => {
    setBusy("rotate");
    const res = await rotateSecret(retireCurrent);
    if (res.ok && res.newKeyFingerprint) {
      append({
        tone: "info",
        text: `$ rotate-secret --retire-current=${retireCurrent} → new key #${res.newKeyFingerprint} (${res.retiredCount} retired)`,
      });
      onMetaChange({
        phpVersion: meta?.phpVersion ?? "",
        opensslLoaded: meta?.opensslLoaded ?? true,
        keyFingerprint: res.newKeyFingerprint,
        retiredCount: res.retiredCount ?? 0,
      });
    } else {
      append({ tone: "error", text: `$ rotate-secret → ${res.error ?? "failed"}` });
    }
    setBusy(null);
  };

  const step3Decrypt = async () => {
    if (!oldPayload) {
      return;
    }
    setBusy("decrypt");
    const res = await decryptString(oldPayload, "");
    if (res.ok) {
      append({
        tone: "ok",
        text: `$ decrypt --key=#${meta?.keyFingerprint ?? "?"} → ok (fell back to retired key #${encryptedUnder})`,
      });
    } else {
      append({
        tone: "error",
        text: `$ decrypt --key=#${meta?.keyFingerprint ?? "?"} → ${res.error ?? "failed"} (key #${encryptedUnder} was not retired)`,
      });
    }
    setBusy(null);
  };

  return (
    <TerminalWindow label="rotate.sh" meta="Keyring">
      <div className="mb-5 flex items-center gap-2.5">
        <KeyRound className="h-4 w-4 text-amber-500" />
        <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-100">Key rotation</span>
      </div>

      <p className="mb-4 text-sm leading-relaxed text-zinc-500 dark:text-zinc-400">
        Rotating the app secret doesn't have to invalidate everything encrypted under the old one.
        Encrypt a sample under the current key, rotate, then try decrypting it again.
      </p>

      {meta && (
        <div className="mb-5 flex flex-wrap gap-2">
          <Flag>--current-key=#{meta.keyFingerprint}</Flag>
          <Flag tone={meta.retiredCount > 0 ? "ok" : undefined}>--retired-keys={meta.retiredCount}</Flag>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <Button type="button" variant="secondary" loading={busy === "encrypt"} onClick={step1Encrypt}>
          1. Encrypt sample
        </Button>

        <label className="flex items-center gap-1.5 font-mono text-xs text-zinc-500 dark:text-zinc-400">
          <input
            type="checkbox"
            checked={retireCurrent}
            onChange={(e) => setRetireCurrent(e.target.checked)}
            className="accent-amber-500"
          />
          retire current key
        </label>
        <Button type="button" variant="secondary" loading={busy === "rotate"} onClick={step2Rotate}>
          2. Rotate secret
        </Button>

        <Button type="button" loading={busy === "decrypt"} disabled={!oldPayload} onClick={step3Decrypt}>
          3. Decrypt old payload
        </Button>
      </div>

      {log.length > 0 && (
        <div className="mt-5 space-y-1.5 overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950 px-3.5 py-3">
          {log.map((line, i) => (
            <div
              key={i}
              className={`font-mono text-xs break-all ${
                line.tone === "ok" ? "text-emerald-400" : line.tone === "error" ? "text-red-400" : "text-zinc-400"
              }`}
            >
              {line.text}
            </div>
          ))}
        </div>
      )}
    </TerminalWindow>
  );
}
