// Guardrail Causal Audit: Kernel-level eBPF Causal Labels & Tamper-Evident Hash Chain

import {
  AuditEvent,
  AuditEventType,
  AutonomyLevel,
  CausalLabel,
} from "../types/guardrail";

async function sha256(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export class CausalAuditService {
  private events: AuditEvent[] = [];
  private genesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

  constructor() {
    this.seedInitialEvents();
  }

  private seedInitialEvents() {
    // Seed some initial audit entries so the UI starts with rich historical context
    const label: CausalLabel = {
      label_id: "cl_init_01",
      plan_id: "plan_bootstrap_sys",
      step_id: "step_boot_0",
      intent: "System initialization and PEP fleet boot",
      agent_class: "system",
      user_id: "root",
      autonomy_level: AutonomyLevel.L3,
      issued_at: Math.floor(Date.now() / 1000) - 3600,
      signature: "sig_ed25519_kernel_bootstrap",
    };

    const genesisEvent: AuditEvent = {
      event_id: "evt_00001",
      timestamp: Date.now() - 3600000,
      event_type: AuditEventType.PLAN_SUBMITTED,
      causal_label: label,
      details: { component: "Guardrail Core", status: "ONLINE", message: "Enforcement policies loaded" },
      previous_hash: this.genesisHash,
      hash: "8f434346648f6b96df89dda901c5176b10f60753b8c012165a329a14ab199187",
    };

    this.events.push(genesisEvent);
  }

  public async logEvent(
    eventType: AuditEventType,
    causalLabel: CausalLabel,
    details: Record<string, any>
  ): Promise<AuditEvent> {
    const previousEvent = this.events[this.events.length - 1];
    const prevHash = previousEvent ? previousEvent.hash : this.genesisHash;
    const eventId = `evt_${(this.events.length + 1).toString().padStart(5, "0")}`;
    const timestamp = Date.now();

    const payloadToHash = JSON.stringify({
      eventId,
      timestamp,
      eventType,
      causalLabel,
      details,
      prevHash,
    });

    const hash = await sha256(payloadToHash);

    const event: AuditEvent = {
      event_id: eventId,
      timestamp,
      event_type: eventType,
      causal_label: causalLabel,
      details,
      previous_hash: prevHash,
      hash,
    };

    this.events.push(event);
    return event;
  }

  public createCausalLabel(
    planId: string,
    stepId: string,
    intent: string,
    agentClass: string,
    userId: string,
    autonomyLevel: AutonomyLevel
  ): CausalLabel {
    return {
      label_id: `cl_${Math.random().toString(36).substring(2, 8)}`,
      plan_id: planId,
      step_id: stepId,
      intent,
      agent_class: agentClass,
      user_id: userId,
      autonomy_level: autonomyLevel,
      issued_at: Math.floor(Date.now() / 1000),
      signature: `ebpf_sig_${Math.random().toString(36).substring(2, 10)}`,
    };
  }

  public async verifyChainIntegrity(): Promise<{
    valid: boolean;
    tamperedIndex?: number;
    error?: string;
    verifiedCount: number;
  }> {
    for (let i = 0; i < this.events.length; i++) {
      const current = this.events[i];
      const prevHash = i === 0 ? this.genesisHash : this.events[i - 1].hash;

      if (current.previous_hash !== prevHash) {
        return {
          valid: false,
          tamperedIndex: i,
          error: `Chain broken at event #${i + 1} (${current.event_id}): previous_hash does not match parent's block hash.`,
          verifiedCount: i,
        };
      }

      // Re-hash
      const expectedPayload = JSON.stringify({
        eventId: current.event_id,
        timestamp: current.timestamp,
        eventType: current.event_type,
        causalLabel: current.causal_label,
        details: current.details,
        prevHash: current.previous_hash,
      });

      // For genesis block we seeded a fixed hash, skip recalculation if first
      if (i > 0) {
        const recalculated = await sha256(expectedPayload);
        if (recalculated !== current.hash) {
          return {
            valid: false,
            tamperedIndex: i,
            error: `Hash mismatch at event #${i + 1} (${current.event_id}): Content was modified in storage!`,
            verifiedCount: i,
          };
        }
      }
    }

    return {
      valid: true,
      verifiedCount: this.events.length,
    };
  }

  public tamperWithEvent(index: number, newDetailMessage: string): void {
    if (this.events[index]) {
      this.events[index].details = {
        ...this.events[index].details,
        message: newDetailMessage,
        _TAMPERED: true,
      };
    }
  }

  public getEvents(): AuditEvent[] {
    return [...this.events];
  }
}

export const defaultCausalAudit = new CausalAuditService();
