"""Evidence-aware activation layer for Guardrail.

This module handles the integration of evidence (test results, logs, metrics) into agent activation decisions, ensuring that actions are only executed when sufficient evidence supports their safety and reliability.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import json
import os

@dataclass
class EvidenceItem:
    """Represents a single piece of evidence."""
    id: str
    source: str  # e.g., 'test', 'log', 'metric'
    timestamp: str
    data: Dict[str, Any]
    confidence: float  # 0.0 to 1.0

@dataclass
class EvidenceCollection:
    """Collection of evidence items."""
    items: List[EvidenceItem]
    last_updated: str

class EvidenceProcessor:
    """Processes and validates evidence for activation decisions."""
    
    def __init__(self, evidence_dir: str = "/root/guardrail/evidence"):
        self.evidence_dir = evidence_dir
        self._ensure_directory_exists()
    
    def _ensure_directory_exists(self):
        """Ensure the evidence directory exists."""
        os.makedirs(self.evidence_dir, exist_ok=True)
    
    def load_evidence(self, evidence_id: str) -> Optional[EvidenceItem]:
        """Load evidence by ID."""
        path = os.path.join(self.evidence_dir, f"{evidence_id}.json")
        if not os.path.exists(path):
            return None
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            return EvidenceItem(
                id=evidence_id,
                source=data.get('source', 'unknown'),
                timestamp=data.get('timestamp', ''),
                data=data.get('data', {}),
                confidence=data.get('confidence', 0.0)
            )
        except Exception as e:
            print(f"Error loading evidence {evidence_id}: {e}")
            return None
    
    def validate_evidence(self, evidence: EvidenceItem) -> bool:
        """Validate evidence meets minimum requirements."""
        if evidence.confidence < 0.7:
            return False
        if not evidence.data:
            return False
        return True
    
    def get_evidence_for_action(self, action_type: str, resource: str) -> List[EvidenceItem]:
        """Get evidence relevant to a specific action and resource."""
        # In a real implementation, this would query evidence sources
        # For now, we simulate with dummy evidence
        return [
            EvidenceItem(
                id=f"{action_type}_{resource}_{i}",
                source="test",
                timestamp="2026-01-01T00:00:00Z",
                data={"passed": True, "metrics": {"success_rate": 0.95}},
                confidence=0.92
            ) for i in range(3)
        ]
    
    def should_execute_action(self, action_type: str, resource: str, evidence_id: str = None) -> bool:
        """Determine if an action should be executed based on evidence."""
        evidence = self.get_evidence_for_action(action_type, resource)
        if evidence_id:
            evidence = [e for e in evidence if e.id == evidence_id]
        
        if not evidence:
            return False
        
        # Check if all evidence items are valid
        for item in evidence:
            if not self.validate_evidence(item):
                return False
        
        # Calculate average confidence
        avg_confidence = sum(item.confidence for item in evidence) / len(evidence)
        return avg_confidence >= 0.8  # Threshold for execution

# Example usage
if __name__ == "__main__":
    processor = EvidenceProcessor()
    should_execute = processor.should_execute_action(
        action_type="file_write",
        resource="config.yaml",
        evidence_id="test_config_001"
    )
    print(f"Should execute action: {should_execute}")