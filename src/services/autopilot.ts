// Guardrail Autopilot Trust Scoring - Closed-loop autonomy elevation

import {
  AutonomyLevel,
  TrustLevel,
  TrustProfile,
} from "../types/guardrail";

export class AutopilotService {
  private profiles: Map<string, TrustProfile> = new Map();

  constructor() {
    this.seedProfiles();
  }

  private seedProfiles() {
    const defaultAgent: TrustProfile = {
      agent_id: "agent-coding-01",
      user_id: "developer_01",
      agent_class: "coding",
      base_autonomy_level: AutonomyLevel.L1,
      current_trust_level: TrustLevel.PROTECTED,
      trust_score: 45.0,
      total_events: 18,
      violation_count: 0,
      success_count: 18,
      rollback_count: 0,
      last_evaluation: Date.now(),
      elevation_history: [
        {
          timestamp: Date.now() - 86400000,
          old_level: TrustLevel.LOCKED,
          new_level: TrustLevel.PROTECTED,
          reason: "Completed 10 initial tasks with zero policy faults",
          score: 35.0,
        },
      ],
    };

    const sysadminAgent: TrustProfile = {
      agent_id: "agent-ops-02",
      user_id: "devops_lead",
      agent_class: "sysadmin",
      base_autonomy_level: AutonomyLevel.L2,
      current_trust_level: TrustLevel.UNRESTRICTED,
      trust_score: 72.5,
      total_events: 42,
      violation_count: 1,
      success_count: 41,
      rollback_count: 1,
      last_evaluation: Date.now(),
      elevation_history: [
        {
          timestamp: Date.now() - 172800000,
          old_level: TrustLevel.PROTECTED,
          new_level: TrustLevel.UNRESTRICTED,
          reason: "Sustained >70 score across 30 production runs",
          score: 70.0,
        },
      ],
    };

    this.profiles.set(defaultAgent.agent_id, defaultAgent);
    this.profiles.set(sysadminAgent.agent_id, sysadminAgent);
  }

  public getProfile(agentId: string): TrustProfile {
    let profile = this.profiles.get(agentId);
    if (!profile) {
      profile = {
        agent_id: agentId,
        user_id: "developer_01",
        agent_class: "general",
        base_autonomy_level: AutonomyLevel.L1,
        current_trust_level: TrustLevel.PROTECTED,
        trust_score: 40.0,
        total_events: 0,
        violation_count: 0,
        success_count: 0,
        rollback_count: 0,
        last_evaluation: Date.now(),
        elevation_history: [],
      };
      this.profiles.set(agentId, profile);
    }
    return profile;
  }

  public recordSuccess(agentId: string, details?: string): TrustProfile {
    const profile = this.getProfile(agentId);
    profile.success_count += 1;
    profile.total_events += 1;
    profile.trust_score = Math.min(100.0, profile.trust_score + 2.5);
    this.evaluateLevel(profile, details || "Successful execution without safety violations");
    return { ...profile };
  }

  public recordViolation(agentId: string, reason: string): TrustProfile {
    const profile = this.getProfile(agentId);
    profile.violation_count += 1;
    profile.total_events += 1;
    profile.trust_score = Math.max(0.0, profile.trust_score - 15.0);
    this.evaluateLevel(profile, `Policy violation occurred: ${reason}`);
    return { ...profile };
  }

  public recordConsentApproval(agentId: string): TrustProfile {
    const profile = this.getProfile(agentId);
    profile.total_events += 1;
    profile.trust_score = Math.min(100.0, profile.trust_score + 1.0);
    this.evaluateLevel(profile, "User granted consent for elevated plan");
    return { ...profile };
  }

  public recordConsentDenial(agentId: string): TrustProfile {
    const profile = this.getProfile(agentId);
    profile.total_events += 1;
    profile.trust_score = Math.max(0.0, profile.trust_score - 5.0);
    this.evaluateLevel(profile, "User rejected plan risk escalation");
    return { ...profile };
  }

  public recordRollback(agentId: string): TrustProfile {
    const profile = this.getProfile(agentId);
    profile.rollback_count += 1;
    profile.total_events += 1;
    profile.trust_score = Math.max(0.0, profile.trust_score - 10.0);
    this.evaluateLevel(profile, "Filesystem snapshot rollback triggered");
    return { ...profile };
  }

  private evaluateLevel(profile: TrustProfile, context: string) {
    profile.last_evaluation = Date.now();
    const oldLevel = profile.current_trust_level;
    let newLevel = oldLevel;

    // Thresholds:
    // < 30.0 -> LOCKED (L0)
    // 30.0 - 59.9 -> PROTECTED (L1)
    // 60.0 - 84.9 -> UNRESTRICTED (L2)
    // >= 85.0 -> AUTONOMOUS (L3)

    if (profile.trust_score < 30.0) {
      newLevel = TrustLevel.LOCKED;
    } else if (profile.trust_score < 60.0) {
      newLevel = TrustLevel.PROTECTED;
    } else if (profile.trust_score < 85.0) {
      newLevel = TrustLevel.UNRESTRICTED;
    } else {
      newLevel = TrustLevel.AUTONOMOUS;
    }

    if (newLevel !== oldLevel) {
      profile.current_trust_level = newLevel;
      profile.base_autonomy_level = (newLevel as number) as AutonomyLevel;
      profile.elevation_history.unshift({
        timestamp: Date.now(),
        old_level: oldLevel,
        new_level: newLevel,
        reason: `${newLevel > oldLevel ? "Promoted" : "Demoted"}: ${context} (Score: ${profile.trust_score.toFixed(1)})`,
        score: profile.trust_score,
      });
    }
  }

  public getAllProfiles(): TrustProfile[] {
    return Array.from(this.profiles.values());
  }

  public resetScore(agentId: string, targetScore: number = 50.0): TrustProfile {
    const profile = this.getProfile(agentId);
    profile.trust_score = targetScore;
    this.evaluateLevel(profile, "Manual administrative reset");
    return { ...profile };
  }
}

export const defaultAutopilot = new AutopilotService();
