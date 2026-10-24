# Guardrail Documentation

**Intelligent OS Policy Engine for AI Agents**

Guardrail is the authorization and safety layer for an intelligent operating system. It provides non-bypassable policy enforcement between LLM agents and every actuator (files, shell, network, MCP tools), enforcing intent-bound, per-step, short-lived capabilities on a graduated-autonomy consent ladder with kernel-level causal audit.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture Overview](#architecture-overview)
3. [Core Concepts](#core-concepts)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [API Reference](#api-reference)
7. [Integration Guides](#integration-guides)
8. [Security Model](#security-model)
9. [Monitoring & Observability](#monitoring--observability)
10. [Compliance](#compliance)

---

## Quick Start

### Prerequisites

- Python 3.12+
- NVIDIA Nemotron model access (or compatible LLM)
- Optional: Prometheus, OpenTelemetry collector for monitoring

### Installation

```bash
pip install guardrail
# Or from source:
git clone https://github.com/guardrail/guardrail
cd guardrail
pip install -e .
```

### Minimal Example

```python
from guardrail import GuardrailAgent

# Create an agent with coding capabilities
agent = GuardrailAgent(
    agent_class="coding",
    user_id="user123",
    autonomy_level=2,  # L2: read/write/execute
)

# Execute a plan
result = agent.run(
    intent="Create a config.yaml file and validate it",
    plan_id="config_setup_001"
)

print(f"Plan: {result.plan_id}")
print(f"Steps executed: {len(result.step_results)}")
print(f"Success: {not result.error}")
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Guardrail Stack                          │
├─────────────────────────────────────────────────────────────────┤
│  Consent UI (plan diff · autonomy ladder · "explain deny")     │
├─────────────────────────────────────────────────────────────────┤
│  Plan Compiler (intent → static, analyzable action plan)       │
├─────────────────────────────────────────────────────────────────┤
│  PDP (Cedar policies · risk scoring · AuthZEN interface)       │
│  Token Service (Ed25519 · per-step · intent-bound · ≤15 min)   │
├─────────────────────────────────────────────────────────────────┤
│  PEP Fleet: pep-mcp │ pep-fs (LSFS) │ pep-exec │ pep-net       │
├─────────────────────────────────────────────────────────────────┤
│  Sandbox Substrate: Firecracker microVMs (agent isolation)     │
├─────────────────────────────────────────────────────────────────┤
│  Audit: hash-chained decision log + eBPF causal labels         │
└─────────────────────────────────────────────────────────────────┘
```

### Core Components

| Component | Purpose | Phase |
|-----------|---------|-------|
| **MCP Gateway** | MCP-aware permission gateway with fine-grained intent-scoped permissions | 1 |
| **Plan Compiler** | Intent → structured plan with validation, token generation | 2 |
| **Token Service** | JWT-like tokens with intent binding, per-step tokens | 2 |
| **Consent Manager** | Plan-level consent with risk assessment, step-level approvals | 2 |
| **PEP-FS** | LSFS semantic file system with versioning & rollback | 3 |
| **PEP-Exec** | Firecracker microVM execution sandbox | 3 |
| **PEP-Net** | Network egress policy with domain/IP/port controls | 3 |
| **Causal Audit** | eBPF-style hash-chained audit log with causal labels | 4 |
| **Autopilot** | Trust scoring with closed-loop autonomy elevation | 4 |
| **AuthZEN** | AuthZEN-compatible decision API | 4 |
| **SPIFFE/ID-JAG** | Workload identities & enterprise delegation | 4 |
| **Monitoring** | Prometheus/OpenTelemetry metrics & tracing | 5 |
| **Compliance** | AI Act, NIST 800-53, ISO 27001 automated reporting | 5 |
| **Scaling** | Horizontal scaling, load balancing, multi-tenancy | 5 |

---

## Core Concepts

### Autonomy Levels (L0-L3)

| Level | Name | Capabilities | Human Oversight |
|-------|------|--------------|-----------------|
| L0 | Locked | Read-only (file_read, http_get, file_list) | Every action |
| L1 | Protected | Read/write (file_read/write, http_get/post) | Sensitive actions |
| L2 | Unrestricted | Execute (shell_command, vm_create) | High-risk only |
| L3 | Autonomous | Admin (all actions) | Audit only |

### Agent Classes

| Class | Allowed Tools | Use Case |
|-------|---------------|----------|
| coding | file_*, http_*, shell_*, database_* | Software development |
| data_analysis | file_*, http_*, shell_*, database_* | Data science |
| travel_booking | http_*, shell_*, file_read/write | Travel automation |
| email_comms | http_*, shell_*, file_read/write | Email/communication |
| file_organizer | file_*, http_get/post | File management |

### Token Types

- **Plan Token**: Grants permission to execute an entire plan (15 min TTL)
- **Step Token**: Per-step, intent-bound, non-reusable (15 min TTL)
- **Format**: Base64-encoded JSON with HMAC-SHA256 signature

---

## Installation

### From PyPI (when published)

```bash
pip install guardrail
```

### From Source

```bash
git clone https://github.com/guardrail/guardrail
cd guardrail
pip install -e .[dev,monitoring,compliance,scaling]
```

### Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .[dev]
pip install pytest pytest-cov

# Run tests
pytest tests/ -v
```

---

## Configuration

### Environment Variables

```bash
# Core
GUARDRAIL_SECRET_KEY="your-secret-key-change-in-production"
GUARDRAIL_AUDIT_LOG_PATH="/var/log/guardrail/audit.log"
GUARDRAIL_LSFS_ROOT="/var/lib/guardrail/lsfs"

# NVIDIA/Nemotron
NVIDIA_API_KEY="your-nvidia-api-key"
NVIDIA_BASE_URL="https://integrate.api.nvidia.com/v1"
NVIDIA_MODEL="nvidia/nemotron-3-ultra-550b-a55b"

# Monitoring
PROMETHEUS_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT="http://otel-collector:4317"

# Scaling
CLUSTER_MIN_INSTANCES=2
CLUSTER_MAX_INSTANCES=10
LOAD_BALANCER_ALGORITHM="least_latency"
```

### Configuration File (guardrail.yaml)

```yaml
guardrail:
  secret_key: "${GUARDRAIL_SECRET_KEY}"
  audit_log_path: "${GUARDRAIL_AUDIT_LOG_PATH}"
  lsfs_root: "${GUARDRAIL_LSFS_ROOT}"
  
  # Autonomy defaults
  default_autonomy_level: 1
  max_autonomy_level: 3
  
  # Token settings
  token_ttl_seconds: 900  # 15 minutes
  token_algorithm: "HS256"
  
  # Consent
  consent_ttl_seconds: 3600
  auto_approve_low_risk: false
  
  # PEP settings
  pep_fs:
    enabled: true
    snapshot_interval: 300
    max_versions_per_file: 100
  
  pep_exec:
    enabled: true
    firecracker_path: "/usr/bin/firecracker"
    default_cpu: 1
    default_memory_mib: 128
  
  pep_net:
    enabled: true
    default_deny: true
    require_tls: true
  
  # Autopilot
  autopilot:
    enabled: true
    trust_score_decay_per_day: 0.1
    check_interval_seconds: 60
  
  # Monitoring
  monitoring:
    prometheus_enabled: true
    otel_endpoint: "http://otel-collector:4317"
    metrics_port: 9090
  
  # Compliance
  compliance:
    frameworks:
      - eu_ai_act
      - nist_800_53
      - iso_27001
    auto_assess: true
    report_output_dir: "/var/reports/guardrail"
```

---

## API Reference

### GuardrailAgent

```python
class GuardrailAgent:
    def __init__(
        self,
        agent_class: str = "coding",
        user_id: str = "user",
        autonomy_level: int = 1,
        config_path: Optional[str] = None
    ):
        """Initialize a Guardrail agent."""
    
    def run(
        self,
        intent: str,
        plan_id: Optional[str] = None,
        require_consent: bool = True
    ) -> AgentResult:
        """Execute a plan from natural language intent."""
    
    def create_plan(self, intent: str) -> ValidatedPlan:
        """Compile intent into validated plan."""
    
    def request_consent(self, plan: ValidatedPlan) -> ConsentDecision:
        """Request human consent for plan."""
    
    def execute_step(self, step: ValidatedStep) -> StepResult:
        """Execute a single plan step."""
```

### Plan Compiler

```python
from guardrail.plan_compiler import compile_and_validate_plan

plan = compile_and_validate_plan(
    intent="Create config file and run validation",
    agent_class="coding",
    user_id="user123",
    autonomy_level=2
)

print(f"Plan ID: {plan.id}")
print(f"Steps: {len(plan.steps)}")
print(f"Plan token: {plan.plan_token}")
```

### Token Service

```python
from guardrail.token_service import (
    create_plan_token, create_step_token,
    validate_plan_token, validate_step_token
)

# Create tokens
plan_token = create_plan_token(
    plan_id="plan_001",
    intent="Setup configuration",
    agent_class="coding",
    user_id="user123",
    autonomy_level=2
)

step_token = create_step_token(
    plan_id="plan_001",
    step_id="step_001",
    intent="Write config file",
    agent_class="coding",
    user_id="user123",
    autonomy_level=2
)

# Validate
payload = validate_plan_token(plan_token, "plan_001")
valid = validate_step_token_for_execution(
    "plan_001", "step_001", step_token, "coding", "user123", 2
)
```

### Consent Manager

```python
from guardrail.consent_manager import (
    ConsentManager, ConsentDecision, request_consent_interactive
)

manager = ConsentManager()

# Request consent (auto-approves for testing)
decision = manager.request_consent_interactive(plan, risk_level="medium")

if decision.approved:
    print("Plan approved!")
    for step_id, approved in decision.step_approvals.items():
        print(f"  Step {step_id}: {'✓' if approved else '✗'}")
```

### PEP Framework

```python
from guardrail.pep_framework import PEPRequest, PEPType, enforce_pep
from guardrail.pep_fs import create_pep_fs
from guardrail.pep_exec import create_pep_exec
from guardrail.pep_net import create_pep_net

# Initialize PEPs
pep_fs = create_pep_fs("/tmp/guardrail_lsfs")
pep_exec = create_pep_exec("/tmp/guardrail_firecracker")
pep_net = create_pep_net()

# Enforce via registry
request = PEPRequest(
    pep_type=PEPType.FS,
    token=step_token,
    plan_id="plan_001",
    step_id="step_001",
    agent_class="coding",
    user_id="user123",
    autonomy_level=2,
    action="file_write",
    resource="/etc/config.yaml",
    metadata={"content": "key: value\n"}
)

response = enforce_pep(request)
if response.success:
    print(f"Executed: {response.result}")
```

### Causal Audit

```python
from guardrail.causal_audit import (
    CausalAuditLogger, create_causal_label, log_audit_event, AuditEventType
)

logger = CausalAuditLogger("/var/log/guardrail/audit.log")

label = create_causal_label(
    plan_id="plan_001",
    step_id="step_001",
    intent="Write configuration",
    agent_class="coding",
    user_id="user123",
    autonomy_level=2
)

event = log_audit_event(
    AuditEventType.FILE_ACCESS,
    label,
    syscall="openat",
    args={"path": "/etc/config.yaml", "flags": "O_WRONLY"},
    result=3,
    duration_ns=12500
)

# Verify integrity
assert logger.verify_integrity() is True
```

### Autopilot

```python
from guardrail.autopilot import AutopilotController

autopilot = AutopilotController()
autopilot.start_monitoring(interval_seconds=60)

# Record events
autopilot.on_step_success("agent_001", "plan_001", "step_001")
autopilot.on_policy_violation("agent_001", "plan_001", "step_001", {"reason": "unauthorized"})

# Get status
status = autopilot.get_status("agent_001")
print(f"Trust score: {status['trust_score']}")
print(f"Trust level: {status['trust_level']}")
print(f"Effective autonomy: {status['effective_autonomy_level']}")
```

### AuthZEN / SPIFFE / ID-JAG

```python
from guardrail.authzen import (
    AuthZENDecisionEngine, AuthZENSubject, AuthZENResource, AuthZENAction,
    AuthZENContext, AuthZENDecisionRequest,
    SPIFFEIdentityProvider, IDJAGBroker,
    get_spiffe_provider, get_idjag_broker
)

# Initialize
spiffe = get_spiffe_provider()
idjag = get_idjag_broker()
authzen = AuthZENDecisionEngine()

# Register agent identity
spiffe_id = spiffe.register_agent("agent_001", "coding", "user123", 2)

# Create delegation
delegation_id = idjag.create_delegation(
    delegator_id="admin_001",
    delegatee_id="agent_001",
    scope=["file_read", "file_write", "http_get"],
    constraints={"max_autonomy": 2},
    expires_at=int(time.time()) + 86400
)

# Evaluate AuthZEN request
request = AuthZENDecisionRequest(
    subject=AuthZENSubject(
        subject_id="agent_001",
        subject_type=SubjectType.AGENT,
        spiffe_id=spiffe_id,
        attributes={"user_id": "user123", "agent_class": "coding", "autonomy_level": 2}
    ),
    resource=AuthZENResource(resource_id="/etc/config.yaml", resource_type="file"),
    action=AuthZENAction(action_id="file_write", action_type="write"),
    context=AuthZENContext(
        request_id="req_001",
        timestamp=int(time.time() * 1000),
        environment={
            "plan_id": "plan_001",
            "step_id": "step_001",
            "token": step_token,
            "intent": "Write config file"
        }
    )
)

response = authzen.evaluate(request)
print(f"Decision: {response.decision.value}")
```

---

## Integration Guides

### LangGraph Integration

```python
from guardrail.langgraph_adapter import LangGraphAdapter

adapter = LangGraphAdapter(
    agent_class="coding",
    user_id="user123",
    autonomy_level=2
)

# Build and run workflow
result = adapter.run("Create a config file and validate it")
```

### OpenAI Agents SDK Integration

```python
from guardrail.openai_agents_adapter import OpenAIAgentsAdapter

adapter = OpenAIAgentsAdapter(
    agent_class="coding",
    user_id="user123",
    autonomy_level=2
)

result = adapter.run_agent("Create a config file and validate it")
```

### ReAct Integration

```python
from guardrail.react_adapter import ReActAdapter

adapter = ReActAdapter(
    agent_class="coding",
    user_id="user123",
    autonomy_level=2
)

result = adapter.run("Create a config file and validate it")
summary = adapter.get_summary(result)
```

### NVIDIA Nemotron Integration

```python
from guardrail.nvidia_adapter import NvidiaAdapter

adapter = NvidiaAdapter(
    agent_class="coding",
    user_id="user123",
    autonomy_level=2,
    model_name="nvidia/nemotron-3-ultra-550b-a55b"
)

result = adapter.run_agent("Create a config file and validate it")

# Get function calling tools for NVIDIA
tools = adapter.create_nvidia_function_calling_tools()
```

---

## Security Model

### Threat Model

Guardrail addresses:

1. **Policy Misconfiguration** - Automated validation before deployment
2. **Credential Leakage** - Short-lived tokens, secure vault integration
3. **Code Injection** - Signed binaries, runtime verification
4. **Replay Attacks** - Nonce-based tokens, timestamp validation
5. **Side-Channel Leakage** - Constant-time operations, audit isolation

### Security Controls

| Control | Implementation |
|---------|----------------|
| Least Privilege | Per-step tokens, agent-class policies |
| Defense in Depth | Multiple PEPs (MCP, FS, Exec, Net) |
| Audit & Accountability | Hash-chained causal audit log |
| Integrity Verification | HMAC-signed tokens, hash-chained logs |
| Human Oversight | Graduated autonomy, consent ladder |

### Best Practices

1. **Rotate secrets regularly** - Use secret management (HashiCorp Vault, AWS Secrets Manager)
2. **Monitor audit integrity** - Set up alerts on `guardrail_audit_integrity_checks_total{result="failed"}`
3. **Limit autonomy** - Default to L1, require explicit elevation
4. **Review consent logs** - Regular audit of consent decisions
5. **Update policies** - Keep agent class policies current

---

## Monitoring & Observability

### Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `guardrail_authz_latency_seconds` | Authorization decision latency | > 100ms p99 |
| `guardrail_pep_latency_seconds` | PEP enforcement latency | > 50ms p99 |
| `guardrail_trust_score` | Agent trust score | < 25 (demotion risk) |
| `guardrail_violations_total` | Policy violations | > 0 (immediate) |
| `guardrail_audit_integrity_checks_total{result="failed"}` | Audit tampering | > 0 (critical) |

### Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'guardrail'
    static_configs:
      - targets: ['guardrail:9090']
```

### Grafana Dashboards

Import the provided dashboards:
- `guardrail-overview.json` - System overview
- `guardrail-security.json` - Security events
- `guardrail-performance.json` - Latency/throughput
- `guardrail-compliance.json` - Compliance status

### Distributed Tracing

```python
from guardrail.monitoring import get_tracer

tracer = get_tracer()

with tracer.trace_operation("execute_plan", {"plan_id": "plan_001"}) as span:
    span.set_attribute("agent_class", "coding")
    result = agent.run("Create config file")
```

---

## Compliance

### Supported Frameworks

| Framework | Version | Controls | Auto-Assess |
|-----------|---------|----------|-------------|
| EU AI Act | 2024 | 10 | ✓ |
| NIST 800-53 | Rev. 5 | 10 (selected) | ✓ |
| ISO 27001 | 2022 | 8 (Annex A) | ✓ |

### Generating Reports

```python
from guardrail.compliance import generate_compliance_report, ComplianceFramework

# Generate EU AI Act report
report = generate_compliance_report(ComplianceFramework.EU_AI_ACT)
print(f"Compliance Rate: {report.summary['compliance_rate']}%")

# Export JSON
json_output = reporter.export_report(report, "json")

# Export CSV
csv_output = reporter.export_report(report, "csv")
```

### CI/CD Integration

```yaml
# .github/workflows/compliance.yml
name: Compliance Check
on: [push, pull_request]
jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run compliance check
        run: |
          python -m guardrail.compliance \
            --frameworks eu_ai_act,nist_800_53,iso_27001 \
            --output-dir reports/ \
            --fail-on-below 80%
```

---

## Examples

See the `examples/` directory:

- `quickstart.py` - Minimal working example
- `langgraph_integration.py` - LangGraph workflow
- `openai_agents_integration.py` - OpenAI Agents SDK
- `react_integration.py` - ReAct loop
- `nvidia_nemotron_integration.py` - NVIDIA Nemotron
- `mcp_gateway_demo.py` - MCP gateway demo
- `compliance_report.py` - Compliance report generation
- `scaling_demo.py` - Horizontal scaling demo

Run any example:

```bash
cd examples
python quickstart.py
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Token validation fails | Clock skew | Sync NTP on all nodes |
| Consent denied | Risk level too high | Review risk assessment, adjust autonomy |
| PEP enforcement fails | Resource not in policy | Update agent class policy |
| Audit integrity fails | Log tampering or corruption | Investigate immediately, check backups |
| Trust score not rising | Insufficient successful steps | Execute more low-risk steps |

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Health Check

```bash
curl http://guardrail:8080/health
# Returns: {"status": "healthy", "version": "1.0.0", "components": {...}}
```

---

## Support

- **Documentation**: https://docs.guardrail.io
- **Issues**: https://github.com/guardrail/guardrail/issues
- **Security**: security@guardrail.io
- **Community**: https://discord.gg/guardrail

---

*Guardrail - Safe autonomy for intelligent agents*