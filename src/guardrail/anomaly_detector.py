import time
from typing import Dict, List, Any, Optional

class AnomalyDetector:
    def __init__(self, window_seconds: int = 60, max_actions_per_window: int = 20):
        self.window_seconds = window_seconds
        self.max_actions_per_window = max_actions_per_window
        # agent_id -> [timestamps]
        self.action_history: Dict[str, List[float]] = {}
        # agent_id -> trust_score
        self.trust_scores: Dict[str, float] = {}

    def track_action(self, agent_id: str, action_type: str) -> Dict[str, Any]:
        """
        Monitors action velocity and frequency to detect hijacked runaway loops.
        """
        now = time.time()
        if agent_id not in self.action_history:
            self.action_history[agent_id] = []
            self.trust_scores[agent_id] = 100.0

        # Clean old history
        history = [ts for ts in self.action_history[agent_id] if now - ts < self.window_seconds]
        history.append(now)
        self.action_history[agent_id] = history

        # Calculate velocity
        count = len(history)
        velocity = count / self.window_seconds # actions per second
        
        is_anomaly = count > self.max_actions_per_window
        
        # Adjust trust score
        if is_anomaly:
            self.trust_scores[agent_id] = max(0, self.trust_scores[agent_id] - 10.0)
        else:
            self.trust_scores[agent_id] = min(100.0, self.trust_scores[agent_id] + 0.5)

        return {
            "is_anomaly": is_anomaly,
            "action_count": count,
            "velocity": round(velocity, 4),
            "trust_score": self.trust_scores[agent_id],
            "reason": "Velocity threshold exceeded" if is_anomaly else "Normal activity"
        }

    def get_trust_score(self, agent_id: str) -> float:
        return self.trust_scores.get(agent_id, 100.0)

_detector = None

def get_anomaly_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector
