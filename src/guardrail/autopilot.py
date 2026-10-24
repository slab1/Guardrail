"""Autopilot Trust Scoring - Closed-loop autonomy elevation based on violation-free history."""
import time
import json
import threading
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from guardrail.causal_audit import CausalAuditLogger, get_audit_logger, AuditEventType


class TrustLevel(Enum):
    """Trust levels for autonomy elevation."""
    LOCKED = 0      # L0 - No autonomy, human verification required
    PROTECTED = 1   # L1 - Limited autonomy, basic operations
    UNRESTRICTED = 2  # L2 - Full autonomy with oversight
    AUTONOMOUS = 3  # L3 - Full autonomy, self-governing


class TrustEventType(Enum):
    """Types of events that affect trust score."""
    SUCCESSFUL_EXECUTION = "successful_execution"
    POLICY_VIOLATION = "policy_violation"
    CONSENT_APPROVED = "consent_approved"
    CONSENT_DENIED = "consent_denied"
    TOKEN_VALID = "token_valid"
    TOKEN_INVALID = "token_invalid"
    ROLLBACK_TRIGGERED = "rollback_triggered"
    AUDIT_INTEGRITY_OK = "audit_integrity_ok"
    AUDIT_INTEGRITY_FAILED = "audit_integrity_failed"
    MANUAL_OVERRIDE = "manual_override"


@dataclass
class TrustEvent:
    """Event that affects trust score."""
    event_id: str
    agent_id: str
    event_type: TrustEventType
    timestamp: int
    delta: float  # Score change
    details: Dict[str, Any] = field(default_factory=dict)
    plan_id: Optional[str] = None
    step_id: Optional[str] = None


@dataclass
class TrustProfile:
    """Trust profile for an agent/user."""
    agent_id: str
    user_id: str
    agent_class: str
    base_autonomy_level: int  # Configured autonomy level (0-3)
    current_trust_level: TrustLevel = TrustLevel.LOCKED
    trust_score: float = 0.0  # 0.0 to 100.0
    total_events: int = 0
    violation_count: int = 0
    success_count: int = 0
    last_evaluation: int = 0
    elevation_history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TrustScoringEngine:
    """Trust scoring engine with configurable rules."""
    
    def __init__(self):
        self.profiles: Dict[str, TrustProfile] = {}
        self.events: List[TrustEvent] = []
        self.lock = threading.Lock()
        
        # Scoring rules (delta per event type)
        self.scoring_rules = {
            TrustEventType.SUCCESSFUL_EXECUTION: 0.5,
            TrustEventType.POLICY_VIOLATION: -10.0,
            TrustEventType.CONSENT_APPROVED: 1.0,
            TrustEventType.CONSENT_DENIED: -0.5,
            TrustEventType.TOKEN_VALID: 0.1,
            TrustEventType.TOKEN_INVALID: -5.0,
            TrustEventType.ROLLBACK_TRIGGERED: -2.0,
            TrustEventType.AUDIT_INTEGRITY_OK: 0.2,
            TrustEventType.AUDIT_INTEGRITY_FAILED: -15.0,
            TrustEventType.MANUAL_OVERRIDE: -1.0,
        }
        
        # Elevation thresholds
        self.elevation_thresholds = {
            TrustLevel.LOCKED: 0.0,
            TrustLevel.PROTECTED: 25.0,
            TrustLevel.UNRESTRICTED: 50.0,
            TrustLevel.AUTONOMOUS: 80.0,
        }
        
        # Minimum events required for elevation
        self.min_events_for_elevation = {
            TrustLevel.LOCKED: 0,
            TrustLevel.PROTECTED: 10,
            TrustLevel.UNRESTRICTED: 50,
            TrustLevel.AUTONOMOUS: 200,
        }
        
        # Violation tolerance (max violations per level)
        self.violation_tolerance = {
            TrustLevel.LOCKED: 0,
            TrustLevel.PROTECTED: 1,
            TrustLevel.UNRESTRICTED: 3,
            TrustLevel.AUTONOMOUS: 5,
        }
        
        # Score decay (per day of inactivity)
        self.daily_decay = 0.1
    
    def _calculate_trust_level(self, profile: TrustProfile) -> TrustLevel:
        """Calculate trust level based on score and history."""
        score = profile.trust_score
        events = profile.total_events
        violations = profile.violation_count
        
        # Check each level from highest to lowest
        for level in [TrustLevel.AUTONOMOUS, TrustLevel.UNRESTRICTED, TrustLevel.PROTECTED, TrustLevel.LOCKED]:
            threshold = self.elevation_thresholds[level]
            min_events = self.min_events_for_elevation[level]
            max_violations = self.violation_tolerance[level]
            
            if score >= threshold and events >= min_events and violations <= max_violations:
                return level
        
        return TrustLevel.LOCKED
    
    def record_event(
        self,
        agent_id: str,
        event_type: TrustEventType,
        details: Optional[Dict[str, Any]] = None,
        plan_id: Optional[str] = None,
        step_id: Optional[str] = None
    ) -> TrustEvent:
        """Record a trust event and update profile."""
        with self.lock:
            # Get or create profile
            if agent_id not in self.profiles:
                # We need user_id and agent_class - use defaults for now
                self.profiles[agent_id] = TrustProfile(
                    agent_id=agent_id,
                    user_id=details.get("user_id", "unknown") if details else "unknown",
                    agent_class=details.get("agent_class", "coding") if details else "coding",
                    base_autonomy_level=details.get("autonomy_level", 0) if details else 0,
                )
            
            profile = self.profiles[agent_id]
            
            # Get score delta
            delta = self.scoring_rules.get(event_type, 0.0)
            
            # Create event
            event = TrustEvent(
                event_id=f"evt_{int(time.time() * 1_000_000)}_{hash(agent_id) % 10000:04d}",
                agent_id=agent_id,
                event_type=event_type,
                timestamp=int(time.time() * 1_000_000),
                delta=delta,
                details=details or {},
                plan_id=plan_id,
                step_id=step_id,
            )
            
            self.events.append(event)
            
            # Update profile
            profile.trust_score = max(0.0, min(100.0, profile.trust_score + delta))
            profile.total_events += 1
            profile.last_evaluation = event.timestamp
            
            if event_type == TrustEventType.POLICY_VIOLATION:
                profile.violation_count += 1
            elif event_type == TrustEventType.SUCCESSFUL_EXECUTION:
                profile.success_count += 1
            
            # Check for elevation
            new_level = self._calculate_trust_level(profile)
            if new_level != profile.current_trust_level:
                old_level = profile.current_trust_level
                profile.current_trust_level = new_level
                profile.elevation_history.append({
                    "timestamp": event.timestamp,
                    "from_level": old_level.value,
                    "to_level": new_level.value,
                    "score": profile.trust_score,
                    "trigger_event": event.event_id,
                })
            
            return event
    
    def get_profile(self, agent_id: str) -> Optional[TrustProfile]:
        """Get trust profile for an agent."""
        return self.profiles.get(agent_id)
    
    def get_effective_autonomy(self, agent_id: str) -> int:
        """Get effective autonomy level (min of base and trust)."""
        profile = self.profiles.get(agent_id)
        if not profile:
            return 0
        return min(profile.base_autonomy_level, profile.current_trust_level.value)
    
    def can_elevate(self, agent_id: str, target_level: TrustLevel) -> bool:
        """Check if agent can be elevated to target level."""
        profile = self.profiles.get(agent_id)
        if not profile:
            return False
        
        # Must not exceed base autonomy level
        if target_level.value > profile.base_autonomy_level:
            return False
        
        # Check thresholds
        threshold = self.elevation_thresholds[target_level]
        min_events = self.min_events_for_elevation[target_level]
        max_violations = self.violation_tolerance[target_level]
        
        return (profile.trust_score >= threshold and
                profile.total_events >= min_events and
                profile.violation_count <= max_violations)
    
    def apply_decay(self):
        """Apply daily score decay (call periodically)."""
        with self.lock:
            now = int(time.time() * 1_000_000)
            for profile in self.profiles.values():
                if profile.last_evaluation > 0:
                    days_inactive = (now - profile.last_evaluation) / (24 * 60 * 60 * 1_000_000)
                    if days_inactive > 1:
                        decay = days_inactive * self.daily_decay
                        profile.trust_score = max(0.0, profile.trust_score - decay)
                        # Recalculate level
                        new_level = self._calculate_trust_level(profile)
                        if new_level != profile.current_trust_level:
                            profile.current_trust_level = new_level
                            profile.elevation_history.append({
                                "timestamp": now,
                                "from_level": profile.current_trust_level.value,
                                "to_level": new_level.value,
                                "score": profile.trust_score,
                                "trigger_event": "decay",
                            })


class AutopilotController:
    """Autopilot controller for closed-loop autonomy management."""
    
    def __init__(self, scoring_engine: Optional[TrustScoringEngine] = None):
        self.scoring_engine = scoring_engine or TrustScoringEngine()
        self.audit_logger = get_audit_logger()
        self.active = False
        self.monitoring_thread: Optional[threading.Thread] = None
    
    def start_monitoring(self, interval_seconds: int = 60):
        """Start background monitoring."""
        self.active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self.monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        self.active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
    
    def _monitor_loop(self, interval: int):
        """Background monitoring loop."""
        while self.active:
            try:
                # Apply decay
                self.scoring_engine.apply_decay()
                
                # Verify audit integrity
                integrity_ok = self.audit_logger.verify_integrity()
                for agent_id, profile in self.scoring_engine.profiles.items():
                    self.scoring_engine.record_event(
                        agent_id,
                        TrustEventType.AUDIT_INTEGRITY_OK if integrity_ok else TrustEventType.AUDIT_INTEGRITY_FAILED,
                        {"integrity_ok": integrity_ok}
                    )
                
                time.sleep(interval)
            except Exception:
                pass
    
    def on_step_success(self, agent_id: str, plan_id: str, step_id: str, details: Optional[Dict] = None):
        """Called when a step executes successfully."""
        self.scoring_engine.record_event(
            agent_id,
            TrustEventType.SUCCESSFUL_EXECUTION,
            details,
            plan_id,
            step_id
        )
    
    def on_policy_violation(self, agent_id: str, plan_id: str, step_id: str, details: Optional[Dict] = None):
        """Called when a policy violation occurs."""
        self.scoring_engine.record_event(
            agent_id,
            TrustEventType.POLICY_VIOLATION,
            details,
            plan_id,
            step_id
        )
    
    def on_consent_decision(self, agent_id: str, plan_id: str, approved: bool, details: Optional[Dict] = None):
        """Called when consent is given or denied."""
        event_type = TrustEventType.CONSENT_APPROVED if approved else TrustEventType.CONSENT_DENIED
        self.scoring_engine.record_event(
            agent_id,
            event_type,
            details,
            plan_id
        )
    
    def on_token_validation(self, agent_id: str, plan_id: str, step_id: str, valid: bool):
        """Called when a token is validated."""
        event_type = TrustEventType.TOKEN_VALID if valid else TrustEventType.TOKEN_INVALID
        self.scoring_engine.record_event(
            agent_id,
            event_type,
            {"valid": valid},
            plan_id,
            step_id
        )
    
    def on_rollback(self, agent_id: str, plan_id: str, step_id: str, details: Optional[Dict] = None):
        """Called when a rollback is triggered."""
        self.scoring_engine.record_event(
            agent_id,
            TrustEventType.ROLLBACK_TRIGGERED,
            details,
            plan_id,
            step_id
        )
    
    def get_status(self, agent_id: str) -> Dict[str, Any]:
        """Get autopilot status for an agent."""
        profile = self.scoring_engine.get_profile(agent_id)
        if not profile:
            return {"agent_id": agent_id, "status": "unknown"}
        
        return {
            "agent_id": agent_id,
            "user_id": profile.user_id,
            "agent_class": profile.agent_class,
            "base_autonomy_level": profile.base_autonomy_level,
            "effective_autonomy_level": self.scoring_engine.get_effective_autonomy(agent_id),
            "trust_level": profile.current_trust_level.name,
            "trust_score": round(profile.trust_score, 2),
            "total_events": profile.total_events,
            "success_count": profile.success_count,
            "violation_count": profile.violation_count,
            "can_elevate_to": [
                level.name for level in TrustLevel
                if self.scoring_engine.can_elevate(agent_id, level)
            ],
            "elevation_history": profile.elevation_history[-5:],  # Last 5
        }


# Global autopilot instance
_autopilot: Optional[AutopilotController] = None


def get_autopilot() -> AutopilotController:
    """Get the global autopilot instance."""
    global _autopilot
    if _autopilot is None:
        _autopilot = AutopilotController()
    return _autopilot


def start_autopilot(interval_seconds: int = 60):
    """Start the autopilot monitoring."""
    get_autopilot().start_monitoring(interval_seconds)


def stop_autopilot():
    """Stop the autopilot monitoring."""
    get_autopilot().stop_monitoring()


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    autopilot = AutopilotController()
    
    agent_id = "agent_coding_001"
    
    # Simulate successful executions
    for i in range(15):
        autopilot.on_step_success(agent_id, f"plan_{i}", f"step_{i}", {"user_id": "user1", "agent_class": "coding"})
    
    # Check status
    status = autopilot.get_status(agent_id)
    print(f"Status after 15 successes: {status}")
    
    # Simulate a violation
    autopilot.on_policy_violation(agent_id, "plan_99", "step_01", {"reason": "unauthorized file access"})
    
    status = autopilot.get_status(agent_id)
    print(f"Status after violation: {status}")
    
    # Simulate more successes
    for i in range(40):
        autopilot.on_step_success(agent_id, f"plan_{i+15}", f"step_{i}", {"user_id": "user1", "agent_class": "coding"})
    
    status = autopilot.get_status(agent_id)
    print(f"Status after 40 more successes: {status}")