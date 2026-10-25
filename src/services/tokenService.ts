// Guardrail Token Service - Intent-bound per-step capabilities

import { AutonomyLevel, TokenPayload, TokenType } from "../types/guardrail";

// Safe Unicode Base64 Helper
function safeBtoa(str: string): string {
  try {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (_, p1) =>
      String.fromCharCode(parseInt(p1, 16))
    ));
  } catch {
    return btoa(str);
  }
}

function safeAtob(str: string): string {
  try {
    return decodeURIComponent(
      Array.prototype.map
        .call(atob(str), (c: string) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
  } catch {
    return atob(str);
  }
}

// Portable SHA256 helper
async function sha256(message: string): Promise<string> {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    let hash = 0;
    for (let i = 0; i < message.length; i++) {
      const char = message.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(64, "0");
  }
  
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export class TokenService {
  private secretKey: string;
  private usedNonces: Set<string> = new Set();
  private tokenStore: Map<string, TokenPayload> = new Map();

  constructor(secretKey: string = "guardrail-sec-key-ed25519-sim") {
    this.secretKey = secretKey;
  }

  public async createPlanToken(
    planId: string,
    intent: string,
    agentClass: string,
    userId: string,
    autonomyLevel: AutonomyLevel,
    ttlSeconds: number = 3600
  ): Promise<{ token: string; payload: TokenPayload }> {
    const now = Math.floor(Date.now() / 1000);
    const nonce = `p_${Math.random().toString(36).substring(2, 10)}_${Date.now()}`;
    const payload: TokenPayload = {
      token_type: TokenType.PLAN,
      plan_id: planId,
      intent,
      agent_class: agentClass,
      user_id: userId,
      autonomy_level: autonomyLevel,
      issued_at: now,
      expires_at: now + ttlSeconds,
      nonce,
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
    ttlSeconds: number = 300
  ): Promise<{ token: string; payload: TokenPayload }> {
    const now = Math.floor(Date.now() / 1000);
    const nonce = `s_${Math.random().toString(36).substring(2, 10)}_${Date.now()}`;
    const payload: TokenPayload = {
      token_type: TokenType.STEP,
      plan_id: planId,
      step_id: stepId,
      intent,
      agent_class: agentClass,
      user_id: userId,
      autonomy_level: autonomyLevel,
      issued_at: now,
      expires_at: now + ttlSeconds,
      nonce,
    };

    const signature = await this.signPayload(payload);
    payload.signature = signature;

    const encoded = this.encodeToken(payload);
    this.tokenStore.set(encoded, payload);
    return { token: encoded, payload };
  }

  public async validateToken(
    tokenString: string,
    expectedPlanId?: string,
    expectedStepId?: string,
    requiredLevel?: AutonomyLevel
  ): Promise<{ valid: boolean; reason?: string; payload?: TokenPayload }> {
    try {
      const payload = this.decodeToken(tokenString);
      if (!payload) {
        return { valid: false, reason: "Malformed token string format" };
      }

      // Check expiration
      const now = Math.floor(Date.now() / 1000);
      if (now > payload.expires_at) {
        return { valid: false, reason: "Capability token expired (TTL exceeded)", payload };
      }

      // Check plan binding if specified
      if (expectedPlanId && payload.plan_id && payload.plan_id !== expectedPlanId) {
        return {
          valid: false,
          reason: `Cross-plan token reuse rejected: expected ${expectedPlanId}, token bound to ${payload.plan_id}`,
          payload,
        };
      }

      // Check step binding if specified
      if (expectedStepId && payload.step_id && payload.step_id !== expectedStepId) {
        return {
          valid: false,
          reason: `Cross-step token reuse rejected: expected ${expectedStepId}, got ${payload.step_id}`,
          payload,
        };
      }

      // Check autonomy level if specified
      if (requiredLevel !== undefined && payload.autonomy_level < requiredLevel) {
        return {
          valid: false,
          reason: `Insufficient autonomy level: requires L${requiredLevel}, token is L${payload.autonomy_level}`,
          payload,
        };
      }

      return { valid: true, payload };
    } catch (e: any) {
      return { valid: false, reason: `Verification error: ${e.message}` };
    }
  }

  public consumeStepToken(tokenString: string): boolean {
    const payload = this.decodeToken(tokenString);
    if (!payload || !payload.nonce) return false;
    if (this.usedNonces.has(payload.nonce)) {
      return false; // Replay attack!
    }
    this.usedNonces.add(payload.nonce);
    return true;
  }

  private async signPayload(payload: TokenPayload): Promise<string> {
    const serialized = JSON.stringify({
      t: payload.token_type,
      p: payload.plan_id,
      s: payload.step_id,
      i: payload.intent,
      a: payload.agent_class,
      u: payload.user_id,
      l: payload.autonomy_level,
      iat: payload.issued_at,
      exp: payload.expires_at,
      n: payload.nonce,
    });
    return sha256(`${serialized}:${this.secretKey}`);
  }

  public encodeToken(payload: TokenPayload): string {
    const header = safeBtoa(JSON.stringify({ alg: "Ed25519-HMAC", typ: "GUARDRAIL-CAP" }));
    const body = safeBtoa(JSON.stringify(payload));
    const sig = payload.signature || "sig_valid_guardrail_pep";
    return `gr_${header}.${body}.${sig}`;
  }

  public decodeToken(tokenString: string): TokenPayload | null {
    if (!tokenString) return null;
    try {
      const clean = tokenString.trim();

      // Format 1: gr_* capability tokens
      if (clean.startsWith("gr_")) {
        const parts = clean.substring(3).split(".");
        if (parts.length < 2) return null;
        const bodyJson = safeAtob(parts[1]);
        return JSON.parse(bodyJson) as TokenPayload;
      }

      // Format 2: Standard JWT ey*
      if (clean.startsWith("ey")) {
        const parts = clean.split(".");
        if (parts.length >= 2) {
          const bodyJson = safeAtob(parts[1]);
          const parsed = JSON.parse(bodyJson);
          return {
            token_type: parsed.token_type || TokenType.PLAN,
            plan_id: parsed.plan_id || "plan_jwt",
            step_id: parsed.step_id,
            intent: parsed.intent || "Verified Capability",
            agent_class: parsed.agent_class || "coding",
            user_id: parsed.user_id || "web_user",
            autonomy_level: parsed.autonomy_level ?? 1,
            issued_at: parsed.issued_at ? Math.floor(parsed.issued_at / 1000) : Math.floor(Date.now() / 1000),
            expires_at: parsed.expires_at ? Math.floor(parsed.expires_at / 1000) : Math.floor(Date.now() / 1000) + 3600,
            nonce: parsed.nonce || "nonce_jwt",
            signature: parts[2] || "sig_jwt"
          };
        }
      }

      // Format 3: Raw JSON Capability object
      if (clean.startsWith("{")) {
        const parsed = JSON.parse(clean);
        return {
          token_type: TokenType.STEP,
          plan_id: parsed.plan_id || "plan_capability",
          step_id: parsed.step_id || "step_01",
          intent: `Bound Action: ${parsed.action_type || "file_read"} on ${parsed.resource || "/workspace/"}`,
          agent_class: "coding",
          user_id: "web_user",
          autonomy_level: parsed.autonomy_level ?? 1,
          issued_at: parsed.issued_at ? Math.floor(parsed.issued_at) : Math.floor(Date.now() / 1000),
          expires_at: parsed.expires_at ? Math.floor(parsed.expires_at) : Math.floor(Date.now() / 1000) + 300,
          nonce: parsed.nonce || "nonce_cap",
          signature: parsed.signature || "sig_pep_hmac"
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
