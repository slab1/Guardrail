/**
 * Safe API fetch utility that validates HTTP status and application/json content-type
 * before attempting JSON parsing, preventing unexpected HTML / fallback SyntaxErrors.
 */
export async function safeFetchJson<T = any>(
  url: string,
  options?: RequestInit
): Promise<T | null> {
  try {
    const res = await fetch(url, options);
    const contentType = res.headers.get("content-type");
    if (!res.ok || !contentType || !contentType.includes("application/json")) {
      return null;
    }
    return await res.json();
  } catch (err) {
    return null;
  }
}

export async function fetchJsonOrThrow<T = any>(
  url: string,
  options?: RequestInit
): Promise<T> {
  const res = await fetch(url, options);
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!res.ok) {
    const errMsg = (json && (json.detail || json.message || json.error)) || text || `HTTP ${res.status} Error`;
    throw new Error(errMsg);
  }

  if (json === null) {
    throw new Error("Invalid response format received from server (expected JSON)");
  }

  return json as T;
}
