export interface CryptoResponse {
  ok: boolean;
  result?: string;
  error?: string;
}

export interface MetaResponse {
  phpVersion: string;
  opensslLoaded: boolean;
  keyFingerprint: string;
  retiredCount: number;
}

export interface RotateResponse {
  ok: boolean;
  retiredCurrent?: boolean;
  oldKeyFingerprint?: string;
  newKeyFingerprint?: string;
  retiredCount?: number;
  error?: string;
}

export interface StreamReport {
  ok: boolean;
  originalBytes?: number;
  encryptedBytes?: number;
  chunkSize?: number;
  chunkCount?: number;
  integrityMatch?: boolean;
  tamperDetected?: boolean;
  encryptMs?: number;
  decryptMs?: number;
  error?: string;
}

export interface FileReport {
  ok: boolean;
  originalBytes?: number;
  payloadBytes?: number;
  payload?: string;
  integrityMatch?: boolean;
  tamperDetected?: boolean;
  encryptMs?: number;
  decryptMs?: number;
  error?: string;
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

export function rotateSecret(retireCurrent: boolean): Promise<RotateResponse> {
  return postJson<RotateResponse>(`${API_BASE}rotate.php`, { retireCurrent });
}

export async function runStreamedRoundTrip(
  file: File,
  password: string,
  chunkSize: number,
): Promise<StreamReport> {
  const form = new FormData();
  form.append("file", file);
  form.append("password", password);
  form.append("chunkSize", String(chunkSize));

  const res = await fetch(`${API_BASE}stream.php`, {
    method: "POST",
    credentials: "same-origin",
    body: form,
  });

  return (await res.json()) as StreamReport;
}

export async function runFileRoundTrip(file: File, password: string): Promise<FileReport> {
  const form = new FormData();
  form.append("file", file);
  form.append("password", password);

  const res = await fetch(`${API_BASE}file.php`, {
    method: "POST",
    credentials: "same-origin",
    body: form,
  });

  return (await res.json()) as FileReport;
}
