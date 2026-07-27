export interface CryptoResponse {
  ok: boolean;
  result?: string;
  error?: string;
}

export interface MetaResponse {
  phpVersion: string;
  opensslLoaded: boolean;
  keyFingerprint: string;
}

// Relative to wherever this app is mounted (see the `base` comment in vite.config.ts), so the
// API calls keep working whether this is served at the domain root or aliased under a subpath.
const API_BASE = `${import.meta.env.BASE_URL}api/`;

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body),
  });

  return (await res.json()) as T;
}

export function encryptString(plaintext: string, password: string): Promise<CryptoResponse> {
  return postJson<CryptoResponse>(`${API_BASE}encrypt.php`, { plaintext, password });
}

export function decryptString(payload: string, password: string): Promise<CryptoResponse> {
  return postJson<CryptoResponse>(`${API_BASE}decrypt.php`, { payload, password });
}

export async function fetchMeta(): Promise<MetaResponse> {
  const res = await fetch(`${API_BASE}meta.php`, { credentials: "same-origin" });
  return (await res.json()) as MetaResponse;
}
