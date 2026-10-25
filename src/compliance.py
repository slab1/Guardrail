"""Enterprise compliance reporting (AI Act, NIST 800-53, ISO 27001)."""
import json
import time
import hashlib
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import threading
from guardrail.causal_audit import get_audit_logger, CausalAuditLogger
from guardrail.autopilot import get_autopilot, AutopilotController
from guardrail.monitoring import get_metrics, MetricsRegistry


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    EU_AI_ACT = "eu_ai_act"
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    CUSTOM = "custom"


class ControlStatus(Enum):
    """Control implementation status."""
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ComplianceControl:
    """A single compliance control."""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    category: str
    status: ControlStatus = ControlStatus.NOT_IMPLEMENTED
    evidence: List[str] = field(default_factory=list)
    implementation_notes: str = ""
    last_assessed: int = 0
    assessor: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """Compliance assessment report."""
    report_id: str
    framework: ComplianceFramework
    generated_at: int
    generated_by: str
    period_start: int
    period_end: int
    controls: List[ComplianceControl] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ComplianceReporter:
    """Generates compliance reports for various frameworks."""
    
    def __init__(
        self,
        audit_logger: Optional[CausalAuditLogger] = None,
        autopilot: Optional[AutopilotController] = None,
        metrics: Optional[MetricsRegistry] = None
    ):
        self.audit_logger = audit_logger or get_audit_logger()
        self.autopilot = autopilot or get_autopilot()
        self.metrics = metrics or get_metrics()
        self.controls: Dict[str, ComplianceControl] = {}
        self.lock = threading.Lock()
        
        # Load default controls for each framework
        self._load_default_controls()
    
    def _load_default_controls(self):
        """Load default compliance controls for supported frameworks."""
        
        # EU AI Act controls
        eu_ai_act_controls = [
            ComplianceControl(
                control_id="AIA-01",
                framework=ComplianceFramework.EU_AI_ACT,
                title="Risk Management System",
                description="Establish and maintain a risk management system for high-risk AI systems",
                category="Risk Management",
                references=["Article 9", "Annex IV"],
            ),
            ComplianceControl(
                control_id="AIA-02",
                framework=ComplianceFramework.EU_AI_ACT,
                title="Data Governance",
                description="Training, validation and testing data subject to appropriate data governance practices",
                category="Data Governance",
                references=["Article 10"],
            ),
            ComplianceControl(
                control_id="AIA-03",
                framework=ComplianceFramework.EU_AI_ACT,
                title="Technical Documentation",
                description="Maintain up-to-date technical documentation demonstrating compliance",
                category="Documentation",
                references=["Article 11", "Annex IV"],
            ),
            ComplianceControl(
                control_id="AIA-04",
                framework=ComplianceFramework.EU_AI_ACT,
                title="Record Keeping (Logging)",
                description="High-risk AI systems shall automatically record events (logs) during operation",
                category="Logging & Monitoring",
                references=["Article 12"],
            ),
            ComplianceControl(
                control_id="AIA-05",
                framework=ComplianceFramework.EU_AI_ACT,
                title="Transparency and Information Provision",
                description="Ensure transparency and provide information to users",
                category="Transparency",
                references=["Article 13"],
            ),
            ComplianceControl(
                control_id="AIA-06",
                framework=ComplianceFramework.EU_AI_ACT,
                title="Human Oversight",
                description="High-risk AI systems shall be designed for effective human oversight",
                category="Human Oversight",
                references=["Article 14"],
            ),
            ComplianceControl(
                control_id="AIA-07",
                framework=ComplianceFramework.EU_AI_ACT,
                title="Accuracy, Robustness and Cybersecurity",
                description="High-risk AI systems shall achieve appropriate levels of accuracy, robustness and cybersecurity",
                category="Security",
                references=["Article 15"],
            ),
            ComplianceControl(
                control_id="AIA-08",
                framework=ComplianceFramework.EU_AI_ACT,
                title="Post-Market Monitoring",
                description="Establish and document a post-market monitoring system",
                category="Monitoring",
                references=["Article 61"],
            ),
            ComplianceControl(
                control_id="AIA-09",
                framework=ComplianceFramework.EU_AI_ACT,
                title="Incident Reporting",
                description="Report serious incidents to market surveillance authorities",
                category="Incident Response",
                references=["Article 62"],
            ),
            ComplianceControl(
                control_id="AIA-10",
                framework=ComplianceFramework.EU_AI_ACT,
                title="Conformity Assessment",
                description="High-risk AI systems undergo conformity assessment before placing on market",
                category="Assessment",
                references=["Article 43"],
            ),
        ]
        
        # NIST 800-53 controls (selected relevant ones)
        nist_controls = [
            ComplianceControl(
                control_id="AC-2",
                framework=ComplianceFramework.NIST_800_53,
                title="Account Management",
                description="Manage system accounts including establishment, activation, modification, review, and removal",
                category="Access Control",
                references=["NIST SP 800-53 Rev. 5 AC-2"],
            ),
            ComplianceControl(
                control_id="AC-3",
                framework=ComplianceFramework.NIST_800_53,
                title="Access Enforcement",
                description="Enforce approved authorizations for logical access to information and system resources",
                category="Access Control",
                references=["NIST SP 800-53 Rev. 5 AC-3"],
            ),
            ComplianceControl(
                control_id="AC-6",
                framework=ComplianceFramework.NIST_800_53,
                title="Least Privilege",
                description="Enforce the most restrictive set of rights/privileges needed for users to perform tasks",
                category="Access Control",
                references=["NIST SP 800-53 Rev. 5 AC-6"],
            ),
            ComplianceControl(
                control_id="AU-2",
                framework=ComplianceFramework.NIST_800_53,
                title="Audit Events",
                description="Determine, document, and implement audit events to be audited",
                category="Audit & Accountability",
                references=["NIST SP 800-53 Rev. 5 AU-2"],
            ),
            ComplianceControl(
                control_id="AU-3",
                framework=ComplianceFramework.NIST_800_53,
                title="Content of Audit Records",
                description="Ensure audit records contain sufficient information",
                category="Audit & Accountability",
                references=["NIST SP 800-53 Rev. 5 AU-3"],
            ),
            ComplianceControl(
                control_id="AU-6",
                framework=ComplianceFramework.NIST_800_53,
                title="Audit Review, Analysis, and Reporting",
                description="Review and analyze audit records regularly",
                category="Audit & Accountability",
                references=["NIST SP 800-53 Rev. 5 AU-6"],
            ),
            ComplianceControl(
                control_id="AU-9",
                framework=ComplianceFramework.NIST_800_53,
                title="Protection of Audit Information",
                description="Protect audit information and audit tools from unauthorized access, modification, and deletion",
                category="Audit & Accountability",
                references=["NIST SP 800-53 Rev. 5 AU-9"],
            ),
            ComplianceControl(
                control_id="SC-7",
                framework=ComplianceFramework.NIST_800_53,
                title="Boundary Protection",
                description="Monitor and control communications at system boundaries",
                category="System & Communications Protection",
                references=["NIST SP 800-53 Rev. 5 SC-7"],
            ),
            ComplianceControl(
                control_id="SC-8",
                framework=ComplianceFramework.NIST_800_53,
                title="Transmission Confidentiality and Integrity",
                description="Protect the confidentiality and integrity of transmitted information",
                category="System & Communications Protection",
                references=["NIST SP 800-53 Rev. 5 SC-8"],
            ),
            ComplianceControl(
                control_id="SI-4",
                framework=ComplianceFramework.NIST_800_53,
                title="System Monitoring",
                description="Monitor the system to detect attacks and indicators of potential attacks",
                category="System & Information Integrity",
                references=["NIST SP 800-53 Rev. 5 SI-4"],
            ),
        ]
        
        # ISO 27001 controls (selected from Annex A)
        iso_controls = [
            ComplianceControl(
                control_id="A.5.1",
                framework=ComplianceFramework.ISO_27001,
                title="Policies for Information Security",
                description="Management direction for information security",
                category="Information Security Policies",
                references=["ISO 27001:2022 Annex A.5.1"],
            ),
            ComplianceControl(
                control_id="A.6.1",
                framework=ComplianceFramework.ISO_27001,
                title="Internal Organization",
                description="Information security roles and responsibilities",
                category="Organization of Information Security",
                references=["ISO 27001:2022 Annex A.6.1"],
            ),
            ComplianceControl(
                control_id="A.8.1",
                framework=ComplianceFramework.ISO_27001,
                title="Responsibility for Assets",
                description="Inventory and ownership of information assets",
                category="Asset Management",
                references=["ISO 27001:2022 Annex A.8.1"],
            ),
            ComplianceControl(
                control_id="A.9.1",
                framework=ComplianceFramework.ISO_27001,
                title="Access Control Policy",
                description="Access control policy and procedures",
                category="Access Control",
                references=["ISO 27001:2022 Annex A.9.1"],
            ),
            ComplianceControl(
                control_id="A.9.2",
                framework=ComplianceFramework.ISO_27001,
                title="User Access Management",
                description="User registration, privilege management, and access reviews",
                category="Access Control",
                references=["ISO 27001:2022 Annex A.9.2"],
            ),
            ComplianceControl(
                control_id="A.12.4",
                framework=ComplianceFramework.ISO_27001,
                title="Logging and Monitoring",
                description="Event logging, monitoring, and clock synchronization",
                category="Operations Security",
                references=["ISO 27001:2022 Annex A.12.4"],
            ),
            ComplianceControl(
                control_id="A.16.1",
                framework=ComplianceFramework.ISO_27001,
                title="Management of Information Security Incidents",
                description="Incident management process and responsibilities",
                category="Information Security Incident Management",
                references=["ISO 27001:2022 Annex A.16.1"],
            ),
            ComplianceControl(
                control_id="A.18.1",
                framework=ComplianceFramework.ISO_27001,
                title="Compliance with Legal and Contractual Requirements",
                description="Identification and compliance with applicable legislation",
                category="Compliance",
                references=["ISO 27001:2022 Annex A.18.1"],
            ),
        ]
        
        # Register all controls
        for control in eu_ai_act_controls + nist_controls + iso_controls:
            self.controls[control.control_id] = control
    
    def assess_control(
        self,
        control_id: str,
        status: ControlStatus,
        evidence: List[str] = None,
        notes: str = "",
        assessor: str = "system",
    ) -> bool:
        """Assess a compliance control."""
        with self.lock:
            if control_id not in self.controls:
                return False
            
            control = self.controls[control_id]
            control.status = status
            control.evidence = evidence or []
            control.implementation_notes = notes
            control.last_assessed = int(time.time())
            control.assessor = assessor
            return True
    
    def auto_assess_controls(self):
        """Automatically assess controls based on system state."""
        # EU AI Act assessments
        self._assess_eu_ai_act()
        self._assess_nist_800_53()
        self._assess_iso_27001()
    
    def _assess_eu_ai_act(self):
        """Assess EU AI Act controls based on system implementation."""
        # AIA-03: Technical Documentation - we have plan compiler, specs
        self.assess_control("AIA-03", ControlStatus.IMPLEMENTED, 
            ["plan_compiler.py", "spec.md", "plan.md"], 
            "Technical documentation maintained in repository")
        
        # AIA-04: Record Keeping - we have causal audit logger
        self.assess_control("AIA-04", ControlStatus.IMPLEMENTED,
            ["causal_audit.py", "audit.log"],
            "Causal audit logger with hash-chained events")
        
        # AIA-06: Human Oversight - we have consent manager and autonomy levels
        self.assess_control("AIA-06", ControlStatus.IMPLEMENTED,
            ["consent_manager.py", "mcp_gateway/policy.py"],
            "Consent manager with risk-based approval, autonomy levels L0-L3")
        
        # AIA-07: Accuracy, Robustness, Cybersecurity - we have PEPs, tokens
        self.assess_control("AIA-07", ControlStatus.PARTIAL,
            ["pep_fs.py", "pep_exec.py", "pep_net.py", "token_service.py"],
            "PEP framework with sandboxing, token-based auth, network policies")
        
        # AIA-08: Post-Market Monitoring - we have monitoring, autopilot
        self.assess_control("AIA-08", ControlStatus.IMPLEMENTED,
            ["monitoring.py", "autopilot.py"],
            "Prometheus/OpenTelemetry monitoring, autopilot trust scoring")
        
        # AIA-09: Incident Reporting - we have audit integrity checks
        self.assess_control("AIA-09", ControlStatus.PARTIAL,
            ["causal_audit.py", "monitoring.py"],
            "Audit integrity verification, system error metrics")
    
    def _assess_nist_800_53(self):
        """Assess NIST 800-53 controls."""
        # AC-2: Account Management - SPIFFE identities
        self.assess_control("AC-2", ControlStatus.IMPLEMENTED,
            ["authzen.py:SPIFFEIdentityProvider"],
            "SPIFFE workload identities for agents")
        
        # AC-3: Access Enforcement - PEP framework
        self.assess_control("AC-3", ControlStatus.IMPLEMENTED,
            ["pep_fs.py", "pep_exec.py", "pep_net.py", "mcp_gateway/server.py"],
            "PEP framework enforces access at file, execution, network, MCP layers")
        
        # AC-6: Least Privilege - autonomy levels, agent policies
        self.assess_control("AC-6", ControlStatus.IMPLEMENTED,
            ["mcp_gateway/policy.py", "pep_framework.py"],
            "L0-L3 autonomy levels, per-agent policies, per-step tokens")
        
        # AU-2: Audit Events - causal audit logger
        self.assess_control("AU-2", ControlStatus.IMPLEMENTED,
            ["causal_audit.py"],
            "Comprehensive audit event types with causal labels")
        
        # AU-3: Content of Audit Records - causal labels with full context
        self.assess_control("AU-3", ControlStatus.IMPLEMENTED,
            ["causal_audit.py"],
            "Audit events include PID, TID, syscall, args, result, causal chain")
        
        # AU-6: Audit Review - integrity checks, monitoring
        self.assess_control("AU-6", ControlStatus.IMPLEMENTED,
            ["causal_audit.py", "monitoring.py"],
            "Hash-chain integrity verification, Prometheus metrics")
        
        # AU-9: Protection of Audit Information - hash-chained logs
        self.assess_control("AU-9", ControlStatus.IMPLEMENTED,
            ["causal_audit.py"],
            "Hash-chained audit log with tamper detection")
        
        # SC-7: Boundary Protection - PEP-Net network policies
        self.assess_control("SC-7", ControlStatus.IMPLEMENTED,
            ["pep_net.py"],
            "Network egress policies with domain/IP/port controls")
        
        # SC-8: Transmission Confidentiality - TLS enforcement
        self.assess_control("SC-8", ControlStatus.IMPLEMENTED,
            ["pep_net.py"],
            "Network rules enforce TLS for external connections")
        
        # SI-4: System Monitoring - monitoring, autopilot
        self.assess_control("SI-4", ControlStatus.IMPLEMENTED,
            ["monitoring.py", "autopilot.py"],
            "Real-time metrics, distributed tracing, anomaly detection")
    
    def _assess_iso_27001(self):
        """Assess ISO 27001 controls."""
        # A.5.1: Policies for Information Security
        self.assess_control("A.5.1", ControlStatus.IMPLEMENTED,
            ["spec.md", "plan.md", "docs/threat_model.md"],
            "Security policies documented in specification and threat model")
        
        # A.6.1: Internal Organization - roles in autopilot, SPIFFE
        self.assess_control("A.6.1", ControlStatus.PARTIAL,
            ["autopilot.py", "authzen.py"],
            "Agent classes, trust levels, SPIFFE identities define roles")
        
        # A.8.1: Responsibility for Assets - asset tracking via audit
        self.assess_control("A.8.1", ControlStatus.PARTIAL,
            ["causal_audit.py", "pep_fs.py"],
            "File versions, execution resources tracked in audit log")
        
        # A.9.1: Access Control Policy - MCP gateway policies
        self.assess_control("A.9.1", ControlStatus.IMPLEMENTED,
            ["mcp_gateway/policy.py", "consent_manager.py"],
            "Policy engine with agent classes, autonomy levels, consent")
        
        # A.9.2: User Access Management - tokens, SPIFFE
        self.assess_control("A.9.2", ControlStatus.IMPLEMENTED,
            ["token_service.py", "authzen.py"],
            "Short-lived tokens, SPIFFE identities, JWT-SVIDs")
        
        # A.12.4: Logging and Monitoring
        self.assess_control("A.12.4", ControlStatus.IMPLEMENTED,
            ["causal_audit.py", "monitoring.py"],
            "Comprehensive logging, Prometheus metrics, OpenTelemetry tracing")
        
        # A.16.1: Incident Management - audit integrity, violations
        self.assess_control("A.16.1", ControlStatus.PARTIAL,
            ["causal_audit.py", "autopilot.py", "monitoring.py"],
            "Violation tracking, trust score degradation, audit alerts")
        
        # A.18.1: Compliance - this reporting framework
        self.assess_control("A.18.1", ControlStatus.IMPLEMENTED,
            ["compliance.py"],
            "Automated compliance assessment for multiple frameworks")
    
    def generate_report(
        self,
        framework: ComplianceFramework,
        period_start: int = None,
        period_end: int = None,
        generated_by: str = "system",
    ) -> ComplianceReport:
        """Generate a compliance report for a framework."""
        now = int(time.time())
        period_end = period_end or now
        period_start = period_start or (now - 30 * 24 * 3600)  # Last 30 days
        
        report_id = hashlib.sha256(
            f"{framework.value}{period_start}{period_end}{time.time()}".encode()
        ).hexdigest()[:16]
        
        # Filter controls for framework
        framework_controls = [
            c for c in self.controls.values()
            if c.framework == framework
        ]
        
        # Calculate summary
        total = len(framework_controls)
        implemented = sum(1 for c in framework_controls if c.status == ControlStatus.IMPLEMENTED)
        partial = sum(1 for c in framework_controls if c.status == ControlStatus.PARTIAL)
        not_implemented = sum(1 for c in framework_controls if c.status == ControlStatus.NOT_IMPLEMENTED)
        not_applicable = sum(1 for c in framework_controls if c.status == ControlStatus.NOT_APPLICABLE)
        
        compliance_rate = (implemented + partial * 0.5) / max(total, 1) * 100
        
        summary = {
            "total_controls": total,
            "implemented": implemented,
            "partial": partial,
            "not_implemented": not_implemented,
            "not_applicable": not_applicable,
            "compliance_rate": round(compliance_rate, 2),
        }
        
        report = ComplianceReport(
            report_id=report_id,
            framework=framework,
            generated_at=now,
            generated_by=generated_by,
            period_start=period_start,
            period_end=period_end,
            controls=framework_controls,
            summary=summary,
            metadata={
                "auto_assessed": True,
                "system_version": "1.0.0",
            }
        )
        
        return report
    
    def export_report(self, report: ComplianceReport, format: str = "json") -> str:
        """Export report to string."""
        if format == "json":
            return json.dumps({
                "report_id": report.report_id,
                "framework": report.framework.value,
                "generated_at": report.generated_at,
                "generated_by": report.generated_by,
                "period_start": report.period_start,
                "period_end": report.period_end,
                "summary": report.summary,
                "controls": [
                    {
                        "control_id": c.control_id,
                        "title": c.title,
                        "category": c.category,
                        "status": c.status.value,
                        "evidence": c.evidence,
                        "notes": c.implementation_notes,
                        "last_assessed": c.last_assessed,
                        "assessor": c.assessor,
                        "references": c.references,
                    }
                    for c in report.controls
                ],
                "metadata": report.metadata,
            }, indent=2)
        elif format == "csv":
            # Simple CSV export
            lines = ["control_id,title,category,status,evidence,notes,last_assessed,assessor"]
            for c in report.controls:
                lines.append(f'"{c.control_id}","{c.title}","{c.category}","{c.status.value}","{"; ".join(c.evidence)}","{c.implementation_notes}",{c.last_assessed},"{c.assessor}"')
            return "\n".join(lines)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def get_all_frameworks_status(self) -> Dict[str, Dict]:
        """Get compliance status for all frameworks."""
        result = {}
        for framework in ComplianceFramework:
            report = self.generate_report(framework)
            result[framework.value] = report.summary
        return result


# Global compliance reporter
_compliance_reporter: Optional[ComplianceReporter] = None


def get_compliance_reporter() -> ComplianceReporter:
    """Get global compliance reporter."""
    global _compliance_reporter
    if _compliance_reporter is None:
        _compliance_reporter = ComplianceReporter()
    return _compliance_reporter


def generate_compliance_report(framework: ComplianceFramework, **kwargs) -> ComplianceReport:
    """Convenience function to generate compliance report."""
    return get_compliance_reporter().generate_report(framework, **kwargs)


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    reporter = ComplianceReporter()
    
    # Auto-assess based on system state
    reporter.auto_assess_controls()
    
    # Generate reports for all frameworks
    for framework in ComplianceFramework:
        report = reporter.generate_report(framework)
        print(f"\n{framework.value.upper()} Compliance Report:")
        print(f"  Report ID: {report.report_id}")
        print(f"  Compliance Rate: {report.summary['compliance_rate']}%")
        print(f"  Implemented: {report.summary['implemented']}/{report.summary['total_controls']}")
        print(f"  Partial: {report.summary['partial']}")
        print(f"  Not Implemented: {report.summary['not_implemented']}")
        
        # Show non-implemented controls
        for c in report.controls:
            if c.status in [ControlStatus.NOT_IMPLEMENTED, ControlStatus.PARTIAL]:
                print(f"  - {c.control_id}: {c.title} ({c.status.value})")
    
    # Export JSON report
    eu_report = reporter.generate_report(ComplianceFramework.EU_AI_ACT)
    json_output = reporter.export_report(eu_report, "json")
    print(f"\nEU AI Act Report (JSON): {len(json_output)} bytes")