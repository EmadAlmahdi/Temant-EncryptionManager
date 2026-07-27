import { useEffect, useState, type FormEvent } from "react";
import { Lock, ShieldCheck, Unlock } from "lucide-react";
import { Card } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";
import { Label, TextArea, TextInput } from "../../components/ui/Field";
import { ResultPanel } from "../../components/ui/ResultPanel";
import { Pill } from "../../components/ui/Pill";
import { decryptString, encryptString, fetchMeta, type MetaResponse } from "../../lib/api";

interface OpState {
  loading: boolean;
  tone?: "ok" | "error";
  text?: string;
}

const idle: OpState = { loading: false };

export function EncryptionManagerDemo() {
  const [meta, setMeta] = useState<MetaResponse | null>(null);

  useEffect(() => {
    fetchMeta()
      .then(setMeta)
      .catch(() => setMeta(null));
  }, []);

  const [plaintext, setPlaintext] = useState("");
  const [encryptPassword, setEncryptPassword] = useState("");
  const [encryptState, setEncryptState] = useState<OpState>(idle);

  const [payload, setPayload] = useState("");
  const [decryptPassword, setDecryptPassword] = useState("");
  const [decryptState, setDecryptState] = useState<OpState>(idle);

  const runEncrypt = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setEncryptState({ loading: true });

    const res = await encryptString(plaintext, encryptPassword);

    if (res.ok && res.result !== undefined) {
      setEncryptState({ loading: false, tone: "ok", text: res.result });
      // Feed a successful encryption straight into the decrypt form for a quick round-trip.
      setPayload(res.result);
      setDecryptPassword(encryptPassword);
      setDecryptState(idle);
    } else {
      setEncryptState({ loading: false, tone: "error", text: res.error ?? "Encryption failed." });
    }
  };

  const runDecrypt = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setDecryptState({ loading: true });

    const res = await decryptString(payload, decryptPassword);

    if (res.ok && res.result !== undefined) {
      setDecryptState({ loading: false, tone: "ok", text: res.result });
    } else {
      setDecryptState({ loading: false, tone: "error", text: res.error ?? "Decryption failed." });
    }
  };

  return (
    <div className="mx-auto max-w-4xl px-6 py-14 sm:py-20">
      <header className="mb-10 animate-fade-in">
        <div className="mb-5 inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 via-violet-500 to-fuchsia-500 text-white shadow-xl shadow-violet-500/30">
          <ShieldCheck className="h-7 w-7" />
        </div>
        <h1 className="bg-gradient-to-br from-zinc-900 to-zinc-600 bg-clip-text text-3xl font-bold tracking-tight text-transparent sm:text-4xl dark:from-white dark:to-zinc-400">
          AES-GCM authenticated encryption
        </h1>
        <p className="mt-3 max-w-xl text-sm leading-relaxed text-zinc-500 sm:text-base dark:text-zinc-400">
          Encrypts and decrypts against a random key generated for your browser session. Add a
          password to switch that field to PBKDF2 password-based encryption instead of app-secret
          mode.
        </p>

        {meta && (
          <div className="mt-5 flex flex-wrap gap-2">
            <Pill tone="ok">PHP {meta.phpVersion}</Pill>
            <Pill tone={meta.opensslLoaded ? "ok" : "bad"}>
              OpenSSL {meta.opensslLoaded ? "loaded" : "missing"}
            </Pill>
            <Pill>Session key #{meta.keyFingerprint}</Pill>
          </div>
        )}
      </header>

      <div className="grid gap-5 md:grid-cols-2">
        <Card className="animate-fade-in p-6" style={{ animationDelay: "80ms" }}>
          <div className="mb-5 flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-600 dark:text-indigo-400">
              <Lock className="h-4 w-4" />
            </div>
            <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-100">Encrypt</span>
          </div>
          <form onSubmit={runEncrypt} className="space-y-3.5">
            <div>
              <Label>Plaintext</Label>
              <TextArea
                value={plaintext}
                onChange={(e) => setPlaintext(e.target.value)}
                placeholder="Text to encrypt&hellip;"
                required
              />
            </div>
            <div>
              <Label>Password (optional)</Label>
              <TextInput
                value={encryptPassword}
                onChange={(e) => setEncryptPassword(e.target.value)}
                placeholder="Leave empty for app-secret mode"
              />
            </div>
            <Button type="submit" loading={encryptState.loading}>
              Encrypt
            </Button>
            {encryptState.tone && encryptState.text && (
              <ResultPanel tone={encryptState.tone} text={encryptState.text} />
            )}
          </form>
        </Card>

        <Card className="animate-fade-in p-6" style={{ animationDelay: "160ms" }}>
          <div className="mb-5 flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-500/10 text-violet-600 dark:text-violet-400">
              <Unlock className="h-4 w-4" />
            </div>
            <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-100">Decrypt</span>
          </div>
          <form onSubmit={runDecrypt} className="space-y-3.5">
            <div>
              <Label>Payload</Label>
              <TextArea
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                placeholder="v1:&hellip;"
                required
              />
            </div>
            <div>
              <Label>Password (optional)</Label>
              <TextInput
                value={decryptPassword}
                onChange={(e) => setDecryptPassword(e.target.value)}
                placeholder="Required if encrypted with a password"
              />
            </div>
            <Button type="submit" loading={decryptState.loading}>
              Decrypt
            </Button>
            {decryptState.tone && decryptState.text && (
              <ResultPanel tone={decryptState.tone} text={decryptState.text} />
            )}
          </form>
        </Card>
      </div>
    </div>
  );
}
