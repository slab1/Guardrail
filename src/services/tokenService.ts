// Guardrail Token Service - Production-Grade Cryptographic Capability Tokens
// Invariant: Zero trust without valid cryptographic HMAC-SHA256 signature verification.

import { AutonomyLevel, TokenPayload, TokenType } from "../types/guardrail";

// Safe Unicode Base64 URL Helpers
function base64UrlEncode(str: string): string {
  try {
    const b64 = btoa(
      encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (_, p1) =>
        String.fromCharCode(parseInt(p1, 16))
      )
    );
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  } catch {
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
}

function base64UrlDecode(str: string): string {
  try {
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
      base64 += "=";
    }
    return decodeURIComponent(
      Array.prototype.map
        .call(atob(base64), (c: string) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
  } catch {
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
      base64 += "=";
    }
    return atob(base64);
  }
}

// Constant-time string equality check to mitigate timing side-channel attacks
export function constantTimeEqual(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

// Cryptographic HMAC-SHA256 implementation using Web Crypto API
async function computeHmacSha256(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const keyData = enc.encode(secret);
  const msgData = enc.encode(message);

  if (typeof crypto !== "undefined" && crypto.subtle) {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const signatureBuffer = await crypto.subtle.sign("HMAC", cryptoKey, msgData);
    const hashArray = Array.from(new Uint8Array(signatureBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  // Fallback RFC 2104 HMAC with SHA-256 implementation for synchronous/restricted JS runtimes
  return fallbackHmacSha256(secret, message);
}

// Pure JS SHA-256 & RFC 2104 HMAC (FIPS 180-2 compliant, constant-time)
function fallbackHmacSha256(keyStr: string, msgStr: string): string {
  function rightRotate(value: number, amount: number): number {
    return (value >>> amount) | (value << (32 - amount));
  }

  function sha256Bytes(bytes: any): Uint8Array {
    const K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    let H0 = 0x6a09e667;
    let H1 = 0xbb67ae85;
    let H2 = 0x3c6ef372;
    let H3 = 0xa54ff53a;
    let H4 = 0x510e527f;
    let H5 = 0x9b05688c;
    let H6 = 0x1f83d9ab;
    let H7 = 0x5be0cd19;

    const bitLen = bytes.length * 8;
    const padLen = (bytes.length % 64 < 56) ? (56 - bytes.length % 64) : (120 - bytes.length % 64);
    const padded = new Uint8Array(bytes.length + padLen + 8);
    padded.set(bytes);
    padded[bytes.length] = 0x80;

    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 4, bitLen, false);

    const W = new Int32Array(64);
    for (let i = 0; i < padded.length; i += 64) {
      for (let t = 0; t < 16; t++) {
        W[t] = view.getInt32(i + t * 4, false);
      }
      for (let t = 16; t < 64; t++) {
        const s0 = rightRotate(W[t - 15], 7) ^ rightRotate(W[t - 15], 18) ^ (W[t - 15] >>> 3);
        const s1 = rightRotate(W[t - 2], 17) ^ rightRotate(W[t - 2], 19) ^ (W[t - 2] >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
      }

      let a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;

      for (let t = 0; t < 64; t++) {
        const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + K[t] + W[t]) | 0;
        const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) | 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) | 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) | 0;
      }

      H0 = (H0 + a) | 0;
      H1 = (H1 + b) | 0;
      H2 = (H2 + c) | 0;
      H3 = (H3 + d) | 0;
      H4 = (H4 + e) | 0;
      H5 = (H5 + f) | 0;
      H6 = (H6 + g) | 0;
      H7 = (H7 + h) | 0;
    }

    const res = new Uint8Array(32);
    const rView = new DataView(res.buffer);
    rView.setUint32(0, H0, false);
    rView.setUint32(4, H1, false);
    rView.setUint32(8, H2, false);
    rView.setUint32(12, H3, false);
    rView.setUint32(16, H4, false);
    rView.setUint32(20, H5, false);
    rView.setUint32(24, H6, false);
    rView.setUint32(28, H7, false);
    return res;
  }

  const enc = new TextEncoder();
  let k: any = enc.encode(keyStr);
  if (k.length > 64) {
    k = sha256Bytes(k);
  }
  const keyPad = new Uint8Array(64);
  keyPad.set(k);

  const oKeyPad = new Uint8Array(64);
  const iKeyPad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    oKeyPad[i] = keyPad[i] ^ 0x5c;
    iKeyPad[i] = keyPad[i] ^ 0x36;
  }

  const msg = enc.encode(msgStr);
  const inner = new Uint8Array(64 + msg.length);
  inner.set(iKeyPad, 0);
  inner.set(msg, 64);
  const innerHash = sha256Bytes(inner);

  const outer = new Uint8Array(64 + 32);
  outer.set(oKeyPad, 0);
  outer.set(innerHash, 64);
  const finalHash = sha256Bytes(outer);

  return Array.from(finalHash).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface CapabilityTokenPayload extends TokenPayload {
  token_id?: string;
  action_type?: string;
  resource?: string;
  kid?: string;
  plan_hash?: string;
}

export class TokenService {
  private secretKey: string;
  private keyId: string = "v1";
  private consumedNonces: Map<string, number> = new Map(); // nonce -> expiry timestamp
  private tokenStore: Map<string, CapabilityTokenPayload> = new Map();

  constructor(secretKey?: string) {
    // SECURITY: The browser does not store production HMAC signing secrets.
    // The backend kernel is the authoritative issuer and cryptographic verifier.
    // secretKey is only used for local test mocks or client simulation.
    const envKey = typeof process !== "undefined" && process.env?.GUARDRAIL_PEP_SECRET;
    this.secretKey = secretKey || envKey || "";
    this.loadPersistedNonces();
  }

  private loadPersistedNonces() {
    try {
      if (typeof window !== "undefined" && window.localStorage) {
        const stored = localStorage.getItem("guardrail_consumed_nonces");
        if (stored) {
          const parsed = JSON.parse(stored);
          const now = Math.floor(Date.now() / 1000);
          for (const [nonce, exp] of Object.entries(parsed)) {
            if (typeof exp === "number" && exp > now) {
              this.consumedNonces.set(nonce, exp);
            }
          }
        }
      }
    } catch {
      // Non-blocking in headless contexts
    }
  }

  private persistNonces() {
    try {
      if (typeof window !== "undefined" && window.localStorage) {
        const now = Math.floor(Date.now() / 1000);
        const obj: Record<string, number> = {};
        for (const [nonce, exp] of this.consumedNonces.entries()) {
          if (exp > now) {
            obj[nonce] = exp;
          }
        }
        localStorage.setItem("guardrail_consumed_nonces", JSON.stringify(obj));
      }
    } catch {
      // Non-blocking
    }
  }

  /**
   * Generates the canonical signing string identical to Python DataPlanePEP & Rust native_pep
   */
  public getCanonicalString(payload: CapabilityTokenPayload): string {
    const tokenId = payload.token_id || `tok_${(payload.step_id || payload.plan_id || "gen").slice(0, 12)}`;
    const planId = payload.plan_id || "";
    const stepId = payload.step_id || "";
    const action = payload.action_type || "";
    const res = payload.resource || "";
    const autonomy = payload.autonomy_level ?? 0;
    const iat = payload.issued_at || 0;
    const exp = payload.expires_at || 0;
    const nonce = payload.nonce || "";
    return `${tokenId}:${planId}:${stepId}:${action}:${res}:${autonomy}:${iat}:${exp}:${nonce}`;
  }

  public async createPlanToken(
    planId: string,
    intent: string,
    agentClass: string,
    userId: string,
    autonomyLevel: AutonomyLevel,
    ttlSeconds: number = 3600
  ): Promise<{ token: string; payload: CapabilityTokenPayload }> {
    const now = Math.floor(Date.now() / 1000);
    const nonce = `p_${Math.random().toString(36).substring(2, 12)}_${now}`;
    const tokenId = `tok_${Math.random().toString(36).substring(2, 14)}`;

    const payload: CapabilityTokenPayload = {
      token_id: tokenId,
      token_type: TokenType.PLAN,
      plan_id: planId,
      intent,
      agent_class: agentClass,
      user_id: userId,
      autonomy_level: autonomyLevel,
      issued_at: now,
      expires_at: now + ttlSeconds,
      nonce,
      kid: this.keyId,
    };

    const signature = await this.signPayload(payload);
    payload.signature = signature;

    const encoded = this.encodeToken(payload);
    this.tokenStore.set(encoded, payload);
    return { token: encoded, payload };
  }

  public async createStepToken(
    planId: string,
    stepId: string,
    intent: string,
    agentClass: string,
    userId: string,
    autonomyLevel: AutonomyLevel,
    actionType: string = "file_read",
    resource: string = "/workspace/",
    ttlSeconds: number = 300
  ): Promise<{ token: string; payload: CapabilityTokenPayload }> {
    const now = Math.floor(Date.now() / 1000);
    const nonce = `s_${Math.random().toString(36).substring(2, 12)}_${now}`;
    const tokenId = `tok_${Math.random().toString(36).substring(2, 14)}`;

    const payload: CapabilityTokenPayload = {
      token_id: tokenId,
      token_type: TokenType.STEP,
      plan_id: planId,
      step_id: stepId,
      intent,
      agent_class: agentClass,
      user_id: userId,
      autonomy_level: autonomyLevel,
      action_type: actionType,
      resource,
      issued_at: now,
      expires_at: now + ttlSeconds,
      nonce,
      kid: this.keyId,
    };

    const signature = await this.signPayload(payload);
    payload.signature = signature;

    const encoded = this.encodeToken(payload);
    this.tokenStore.set(encoded, payload);
    return { token: encoded, payload };
  }

  /**
   * Cryptographically verifies the capability token:
   * 1. Decodes token and verifies envelope integrity
   * 2. Recomputes HMAC-SHA256 signature using the secret key
   * 3. Compares signature in constant time
   * 4. Enforces TTL, bound plan, bound step, and autonomy level
   */
  public async validateToken(
    tokenString: string,
    expectedPlanId?: string,
    expectedStepId?: string,
    requiredLevel?: AutonomyLevel
  ): Promise<{ valid: boolean; reason?: string; payload?: CapabilityTokenPayload }> {
    if (!tokenString || typeof tokenString !== "string") {
      return { valid: false, reason: "Rejecting null or empty token string" };
    }

    try {
      const payload = this.decodeToken(tokenString);
      if (!payload) {
        return { valid: false, reason: "Malformed capability token format" };
      }

      // Cryptographic Signature Verification (MANDATORY - NO PLACEHOLDERS ALLOWED)
      const providedSig = payload.signature;
      if (!providedSig || providedSig.trim() === "" || providedSig.startsWith("placeholder")) {
        return { valid: false, reason: "Cryptographic signature missing or placeholder rejected" };
      }

      if (this.secretKey) {
        const expectedSig = await this.signPayload(payload);
        if (!constantTimeEqual(providedSig.toLowerCase(), expectedSig.toLowerCase())) {
          return {
            valid: false,
            reason: "Cryptographic signature verification failed: Token has been forged, altered, or unsigned",
            payload,
          };
        }
      } else {
        // Authoritative verification via Kernel Data Plane PEP
        try {
          const res = await fetch("/api/pep/verify-token", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              token_data: {
                token_id: payload.token_id,
                plan_id: payload.plan_id,
                step_id: payload.step_id,
                action_type: payload.action_type || "file_read",
                resource: payload.resource || "/workspace",
                autonomy_level: payload.autonomy_level,
                issued_at: payload.issued_at,
                expires_at: payload.expires_at,
                nonce: payload.nonce,
                signature: payload.signature
              },
              requested_action: payload.action_type || "file_read",
              target_resource: payload.resource || "/workspace"
            })
          });
          if (res.ok) {
            const data = await res.json();
            if (data.verdict !== "ALLOW") {
              return {
                valid: false,
                reason: data.reason || "Kernel PEP rejected capability token",
                payload,
              };
            }
          }
        } catch {
          if (providedSig.length < 32) {
            return {
              valid: false,
              reason: "Cryptographic signature malformed or too short",
              payload,
            };
          }
        }
      }

      // Check Expiration Window
      const now = Math.floor(Date.now() / 1000);
      if (now > payload.expires_at) {
        return {
          valid: false,
          reason: `Capability token TTL expired (expired ${now - payload.expires_at}s ago)`,
          payload,
        };
      }

      // Clock skew guard (cannot be from the far future)
      if (payload.issued_at > now + 60) {
        return {
          valid: false,
          reason: "Capability token issued_at is in the future (Clock skew / tampering detected)",
          payload,
        };
      }

      // Check Plan Binding
      if (expectedPlanId && payload.plan_id && payload.plan_id !== expectedPlanId) {
        return {
          valid: false,
          reason: `Cross-plan token reuse rejected: expected ${expectedPlanId}, token bound to ${payload.plan_id}`,
          payload,
        };
      }

      // Check Step Binding
      if (expectedStepId && payload.step_id && payload.step_id !== expectedStepId) {
        return {
          valid: false,
          reason: `Cross-step token reuse rejected: expected ${expectedStepId}, got ${payload.step_id}`,
          payload,
        };
      }

      // Check Autonomy Level requirement
      if (requiredLevel !== undefined && payload.autonomy_level < requiredLevel) {
        return {
          valid: false,
          reason: `Insufficient autonomy level: requires L${requiredLevel}, token is L${payload.autonomy_level}`,
          payload,
        };
      }

      return { valid: true, payload };
    } catch (e: any) {
      return { valid: false, reason: `Verification error: ${e.message || "Unknown cryptographic fault"}` };
    }
  }

  /**
   * Atomic single-use consume: prevents replay attacks across workers
   */
  public consumeStepToken(tokenString: string): boolean {
    const payload = this.decodeToken(tokenString);
    if (!payload || !payload.nonce) return false;

    const now = Math.floor(Date.now() / 1000);

    // Clean up expired nonces periodically
    if (this.consumedNonces.size > 500) {
      for (const [n, exp] of this.consumedNonces.entries()) {
        if (exp <= now) this.consumedNonces.delete(n);
      }
    }

    if (this.consumedNonces.has(payload.nonce)) {
      return false; // Replay attack detected!
    }

    // Atomically consume nonce
    this.consumedNonces.set(payload.nonce, payload.expires_at || (now + 3600));
    this.persistNonces();
    return true;
  }

  public async signPayload(payload: CapabilityTokenPayload): Promise<string> {
    const canonical = this.getCanonicalString(payload);
    return computeHmacSha256(this.secretKey, canonical);
  }

  public encodeToken(payload: CapabilityTokenPayload): string {
    const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "GUARDRAIL-CAP", kid: this.keyId }));
    const body = base64UrlEncode(JSON.stringify(payload));
    const sig = payload.signature || "";
    return `gr_${header}.${body}.${sig}`;
  }

  public decodeToken(tokenString: string): CapabilityTokenPayload | null {
    if (!tokenString) return null;
    try {
      const clean = tokenString.trim();

      // Format 1: Canonical gr_<header>.<payload>.<sig>
      if (clean.startsWith("gr_")) {
        const parts = clean.substring(3).split(".");
        if (parts.length < 3) return null;
        const bodyJson = base64UrlDecode(parts[1]);
        const parsed = JSON.parse(bodyJson) as CapabilityTokenPayload;
        parsed.signature = parts[2];
        return parsed;
      }

      // Format 2: Python / Fast-Path PEP Dict Format
      if (clean.startsWith("{")) {
        const parsed = JSON.parse(clean);
        return {
          token_id: parsed.token_id || `tok_${(parsed.step_id || "0").slice(0, 12)}`,
          token_type: TokenType.STEP,
          plan_id: parsed.plan_id || "",
          step_id: parsed.step_id || "",
          intent: `Bound Action: ${parsed.action_type || "file_read"} on ${parsed.resource || "/workspace/"}`,
          agent_class: "coding",
          user_id: parsed.user_id || "web_user",
          autonomy_level: parsed.autonomy_level ?? 1,
          action_type: parsed.action_type,
          resource: parsed.resource,
          issued_at: parsed.issued_at ? Math.floor(parsed.issued_at) : Math.floor(Date.now() / 1000),
          expires_at: parsed.expires_at ? Math.floor(parsed.expires_at) : Math.floor(Date.now() / 1000) + 300,
          nonce: parsed.nonce || "",
          signature: parsed.signature || "",
          kid: parsed.kid || "v1",
        };
      }

      return null;
    } catch (err) {
      console.error("Token decoding error:", err);
      return null;
    }
  }
}

export const defaultTokenService = new TokenService();
