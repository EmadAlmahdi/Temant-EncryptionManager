import { useState, type FormEvent } from "react";
import { Lock, Unlock } from "lucide-react";
import { TerminalWindow } from "../../../components/ui/TerminalWindow";
import { Button } from "../../../components/ui/Button";
import { Label, TextArea, TextInput } from "../../../components/ui/Field";
import { ResultPanel } from "../../../components/ui/ResultPanel";
import { decryptString, encryptString } from "../../../lib/api";

type Mode = "encrypt" | "decrypt";

interface OpState {
  loading: boolean;
  tone?: "ok" | "error";
  text?: string;
  nonce: number;
}

const idle: OpState = { loading: false, nonce: 0 };

export function StringCipherSection() {
  const [mode, setMode] = useState<Mode>("encrypt");
  const [plaintext, setPlaintext] = useState("");
  const [payload, setPayload] = useState("");
  const [password, setPassword] = useState("");
  const [state, setState] = useState<OpState>(idle);

  const changeMode = (next: string) => {
    setMode(next as Mode);
    setState(idle);
  };

  const run = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setState({ loading: true, nonce: 0 });

    const res = mode === "encrypt" ? await encryptString(plaintext, password) : await decryptString(payload, password);
    const nonce = Date.now();

    if (res.ok && res.result !== undefined) {
      setState({ loading: false, tone: "ok", text: res.result, nonce });
      if (mode === "encrypt") {
        setPayload(res.result);
      }
    } else {
      setState({
        loading: false,
        tone: "error",
        text: res.error ?? (mode === "encrypt" ? "Encryption failed." : "Decryption failed."),
        nonce,
      });
    }
  };

  return (
    <TerminalWindow
      tabs={[
        { id: "encrypt", label: "encrypt.sh" },
        { id: "decrypt", label: "decrypt.sh" },
      ]}
      activeTab={mode}
      onTabChange={changeMode}
      meta="AES-256-GCM"
    >
      <div className="mb-5 flex items-center gap-2.5">
        {mode === "encrypt" ? <Lock className="h-4 w-4 text-amber-500" /> : <Unlock className="h-4 w-4 text-amber-500" />}
        <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-100">
          {mode === "encrypt" ? "Encrypt" : "Decrypt"}
        </span>
      </div>

      <form onSubmit={run} className="space-y-3.5">
        <div>
          <Label>{mode === "encrypt" ? "plaintext" : "payload"}</Label>
          <TextArea
            value={mode === "encrypt" ? plaintext : payload}
            onChange={(e) => (mode === "encrypt" ? setPlaintext(e.target.value) : setPayload(e.target.value))}
            placeholder={mode === "encrypt" ? "Text to encrypt&hellip;" : "v1:&hellip;"}
            required
          />
        </div>
        <div>
          <Label>password (optional)</Label>
          <TextInput
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Leave empty for app-secret mode"
          />
        </div>
        <Button type="submit" loading={state.loading}>
          Run {mode}
        </Button>

        {state.tone && state.text && <ResultPanel tone={state.tone} text={state.text} nonce={state.nonce} />}

        {mode === "encrypt" && state.tone === "ok" && (
          <button
            type="button"
            onClick={() => changeMode("decrypt")}
            className="block font-mono text-xs text-amber-600 hover:underline dark:text-amber-400"
          >
            &rarr; switch to decrypt.sh to verify
          </button>
        )}
      </form>
    </TerminalWindow>
  );
}
