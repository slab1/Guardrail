// Guardrail Token Service - Intent-bound per-step capabilities

import { AutonomyLevel, TokenPayload, TokenType } from "../types/guardrail";

// Simple portable hash helper
async function sha256(message: string): Promise<string> {
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
    ttlSeconds: number = 900 // 15 mins
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
    ttlSeconds: number = 300 // 5 mins per step
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
    expectedPlanId: string,
    expectedStepId?: string,
    requiredLevel?: AutonomyLevel
  ): Promise<{ valid: boolean; reason?: string; payload?: TokenPayload }> {
    try {
      const payload = this.decodeToken(tokenString);
      if (!payload) {
        return { valid: false, reason: "Malformed token format" };
      }

      // Check expiration
      const now = Math.floor(Date.now() / 1000);
      if (now > payload.expires_at) {
        return { valid: false, reason: "Token expired (TTL exceeded)", payload };
      }

      // Check plan binding
      if (payload.plan_id !== expectedPlanId) {
        return {
          valid: false,
          reason: `Cross-plan token reuse rejected: expected ${expectedPlanId}, token bound to ${payload.plan_id}`,
          payload,
        };
      }

      // Check step binding if required
      if (expectedStepId && payload.step_id !== expectedStepId) {
        return {
          valid: false,
          reason: `Cross-step token reuse rejected: expected ${expectedStepId}, got ${payload.step_id}`,
          payload,
        };
      }

      // Check autonomy level
      if (requiredLevel !== undefined && payload.autonomy_level < requiredLevel) {
        return {
          valid: false,
          reason: `Insufficient autonomy level: requires L${requiredLevel}, token is L${payload.autonomy_level}`,
          payload,
        };
      }

      // Verify signature
      const expectedSignature = await this.signPayload({
        ...payload,
        signature: undefined,
      });

      if (expectedSignature !== payload.signature) {
        return { valid: false, reason: "Cryptographic signature verification failed", payload };
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
      return false; // Replay attack detected!
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

  private encodeToken(payload: TokenPayload): string {
    const header = btoa(JSON.stringify({ alg: "Ed25519-HMAC", typ: "GUARDRAIL-CAP" }));
    const body = btoa(JSON.stringify(payload));
    const sig = payload.signature || "";
    return `gr_${header}.${body}.${sig}`;
  }

  public decodeToken(tokenString: string): TokenPayload | null {
    try {
      if (!tokenString.startsWith("gr_")) return null;
      const parts = tokenString.substring(3).split(".");
      if (parts.length !== 3) return null;
      const bodyJson = atob(parts[1]);
      return JSON.parse(bodyJson) as TokenPayload;
    } catch {
      return null;
    }
  }
}

export const defaultTokenService = new TokenService();
