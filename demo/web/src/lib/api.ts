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
  return postJson<CryptoResponse>(`/api/encrypt.php`, { plaintext, password });
}

export function decryptString(payload: string, password: string): Promise<CryptoResponse> {
  return postJson<CryptoResponse>(`/api/decrypt.php`, { payload, password });
}

export async function fetchMeta(): Promise<MetaResponse> {
  const res = await fetch(`/api/meta.php`, { credentials: "same-origin" });
  return (await res.json()) as MetaResponse;
}

export function rotateSecret(retireCurrent: boolean): Promise<RotateResponse> {
  return postJson<RotateResponse>(`/api/rotate.php`, { retireCurrent });
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

  const res = await fetch(`/api/stream.php`, {
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

  const res = await fetch(`/api/file.php`, {
    method: "POST",
    credentials: "same-origin",
    body: form,
  });

  return (await res.json()) as FileReport;
}
