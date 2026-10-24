"""Configuration management for Guardrail using Pydantic Settings."""

from typing import Optional, List, Dict, Any
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


class MCPConfig(BaseSettings):
    """MCP Gateway configuration."""
    model_config = SettingsConfigDict(env_prefix="MCP_")
    
    host: str = "0.0.0.0"
    port: int = 9000
    enable_tls: bool = False
    cert_path: Optional[str] = None
    key_path: Optional[str] = None
    max_connections: int = 100
    request_timeout: int = 30


class PlanCompilerConfig(BaseSettings):
    """Plan Compiler configuration."""
    model_config = SettingsConfigDict(env_prefix="PLAN_COMPILER_")
    
    enable_static_validation: bool = True
    enable_reversibility_check: bool = True
    max_plan_steps: int = 100
    default_timeout: int = 300
    allowed_models: List[str] = ["nvidia/nemotron-3-ultra-550b-a55b", "gpt-4", "claude-3"]


class TokenServiceConfig(BaseSettings):
    """Token Service configuration."""
    model_config = SettingsConfigDict(env_prefix="TOKEN_SERVICE_")
    
    secret_key: str = Field(
        default="guardrail-secret-key-change-in-production",
        description="HMAC secret key for token signing"
    )
    algorithm: str = "HS256"
    default_ttl: int = 3600
    max_ttl: int = 86400
    issuer: str = "guardrail"


class ConsentConfig(BaseSettings):
    """Consent Manager configuration."""
    model_config = SettingsConfigDict(env_prefix="CONSENT_")
    
    require_consent_for_risk: List[str] = ["medium", "high", "critical"]
    consent_ttl: int = 3600
    auto_approve_low_risk: bool = True
    ui_callback_url: Optional[str] = None


class PEPConfig(BaseSettings):
    """PEP Framework configuration."""
    model_config = SettingsConfigDict(env_prefix="PEP_")
    
    # PEP-FS (LSFS)
    fs_root: str = "/var/guardrail/fs"
    fs_snapshot_interval: int = 300
    fs_max_snapshots: int = 100
    fs_enable_compression: bool = True
    
    # PEP-Exec (Firecracker)
    exec_kernel_path: str = "/var/guardrail/firecracker/vmlinux"
    exec_rootfs_path: str = "/var/guardrail/firecracker/rootfs.ext4"
    exec_cpu_count: int = 2
    exec_memory_mb: int = 1024
    exec_network_rate_limit: str = "100Mbps"
    
    # PEP-Net
    net_default_policy: str = "deny"
    net_allowed_domains: List[str] = ["api.github.com", "pypi.org"]
    net_tls_required: bool = True
    net_verify_certificates: bool = True


class CausalAuditConfig(BaseSettings):
    """Causal Audit configuration."""
    model_config = SettingsConfigDict(env_prefix="CAUSAL_AUDIT_")
    
    log_path: str = "/var/guardrail/audit/causal.log"
    max_log_size_mb: int = 1000
    retention_days: int = 90
    enable_hash_chain: bool = True
    hash_algorithm: str = "sha256"
    enable_ebpf: bool = False  # Requires kernel support


class AutopilotConfig(BaseSettings):
    """Autopilot Trust Scoring configuration."""
    model_config = SettingsConfigDict(env_prefix="AUTOPILOT_")
    
    initial_trust_score: float = 0.0
    trust_increment: float = 0.5
    trust_decrement: float = 2.0
    elevation_thresholds: Dict[str, float] = {
        "LOCKED": 0,
        "RESTRICTED": 10,
        "STANDARD": 50,
        "ELEVATED": 100,
        "AUTONOMOUS": 200,
    }
    decay_rate: float = 0.01
    max_history: int = 10000


class AuthZENConfig(BaseSettings):
    """AuthZEN/Identity configuration."""
    model_config = SettingsConfigDict(env_prefix="AUTHZEN_")
    
    pdp_endpoint: str = "http://localhost:8081"
    spiffe_trust_domain: str = "guardrail.example.com"
    spiffe_socket_path: str = "/var/run/spire/socket"
    enable_workload_identity: bool = True
    cache_ttl: int = 300


class MeshConfig(BaseSettings):
    """Multi-Agent Mesh configuration."""
    model_config = SettingsConfigDict(env_prefix="MESH_")
    
    node_id: str = Field(default_factory=lambda: "guardrail-node")
    listen_address: str = "0.0.0.0:9000"
    bootstrap_nodes: List[str] = []
    heartbeat_interval: int = 5
    node_timeout: int = 30
    enable_mtls: bool = False
    cert_path: Optional[str] = None
    key_path: Optional[str] = None


class MonitoringConfig(BaseSettings):
    """Monitoring/Observability configuration."""
    model_config = SettingsConfigDict(env_prefix="MONITORING_")
    
    service_name: str = "guardrail"
    otlp_endpoint: str = "http://localhost:4317"
    prometheus_port: int = 9090
    enable_prometheus: bool = True
    enable_otlp: bool = True
    log_level: str = "INFO"
    trace_sample_rate: float = 0.1
    metric_interval: int = 15


class ComplianceConfig(BaseSettings):
    """Compliance configuration."""
    model_config = SettingsConfigDict(env_prefix="COMPLIANCE_")
    
    enable_ai_act: bool = True
    enable_nist_ai_rmf: bool = True
    enable_iso_42001: bool = True
    evidence_path: str = "/var/guardrail/compliance/evidence"
    report_path: str = "/var/guardrail/compliance/reports"
    audit_retention_days: int = 2555  # 7 years


class AdvancedSecurityConfig(BaseSettings):
    """Advanced Security configuration."""
    model_config = SettingsConfigDict(env_prefix="ADV_SEC_")
    
    # HSM
    hsm_type: str = "soft"  # soft, pkcs11, aws_kms, azure_keyvault
    hsm_pkcs11_lib: Optional[str] = None
    hsm_slot: int = 0
    hsm_pin: Optional[str] = None
    
    # Biometric
    biometric_type: str = "fido2"  # fido2, bind, custom
    fido2_rp_id: str = "guardrail.example.com"
    fido2_origin: str = "https://guardrail.example.com"
    
    # Zero Trust
    enable_continuous_auth: bool = True
    authzen_endpoint: str = "http://localhost:8082"


class DisasterRecoveryConfig(BaseSettings):
    """Disaster Recovery configuration."""
    model_config = SettingsConfigDict(env_prefix="DR_")
    
    backup_path: str = "/var/guardrail/backup"
    backup_interval: int = 3600
    retention_days: int = 30
    compression: bool = True
    encryption: bool = True
    replication_regions: List[str] = ["us-east-1", "us-west-2", "eu-west-1"]
    rpo_seconds: int = 300
    rto_seconds: int = 3600


class IntegrationTestConfig(BaseSettings):
    """Integration Testing configuration."""
    model_config = SettingsConfigDict(env_prefix="INT_TEST_")
    
    mcp_server_url: Optional[str] = None
    langgraph_endpoint: Optional[str] = None
    nemotron_api_key: Optional[str] = None
    test_timeout: int = 60
    parallel_tests: int = 4


class GuardrailSettings(BaseSettings):
    """Main Guardrail configuration."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # App
    app_name: str = "guardrail"
    environment: str = "development"  # development, staging, production
    debug: bool = True
    log_level: str = "INFO"
    
    # Paths
    data_dir: str = "/var/guardrail"
    config_dir: str = "/etc/guardrail"
    log_dir: str = "/var/log/guardrail"
    
    # Sub-configs
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    plan_compiler: PlanCompilerConfig = Field(default_factory=PlanCompilerConfig)
    token_service: TokenServiceConfig = Field(default_factory=TokenServiceConfig)
    consent: ConsentConfig = Field(default_factory=ConsentConfig)
    pep: PEPConfig = Field(default_factory=PEPConfig)
    causal_audit: CausalAuditConfig = Field(default_factory=CausalAuditConfig)
    autopilot: AutopilotConfig = Field(default_factory=AutopilotConfig)
    authzen: AuthZENConfig = Field(default_factory=AuthZENConfig)
    mesh: MeshConfig = Field(default_factory=MeshConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    advanced_security: AdvancedSecurityConfig = Field(default_factory=AdvancedSecurityConfig)
    disaster_recovery: DisasterRecoveryConfig = Field(default_factory=DisasterRecoveryConfig)
    integration_test: IntegrationTestConfig = Field(default_factory=IntegrationTestConfig)
    
    def get_database_url(self) -> str:
        """Get database URL (placeholder for future use)."""
        return "sqlite:///guardrail.db"
    
    def get_redis_url(self) -> str:
        """Get Redis URL (placeholder for future use)."""
        return "redis://localhost:6379/0"


# Global settings instance
_settings: Optional[GuardrailSettings] = None


def get_settings() -> GuardrailSettings:
    """Get global settings instance."""
    global _settings
    if _settings is None:
        _settings = GuardrailSettings()
    return _settings


def init_settings(config_path: Optional[str] = None) -> GuardrailSettings:
    """Initialize settings from config file."""
    global _settings
    if config_path:
        # Load from YAML if provided
        import yaml
        with open(config_path) as f:
            config_data = yaml.safe_load(f)
        _settings = GuardrailSettings(**config_data)
    else:
        _settings = GuardrailSettings()
    return _settings


# Convenience functions
def get_mcp_config() -> MCPConfig:
    return get_settings().mcp

def get_plan_compiler_config() -> PlanCompilerConfig:
    return get_settings().plan_compiler

def get_token_service_config() -> TokenServiceConfig:
    return get_settings().token_service

def get_consent_config() -> ConsentConfig:
    return get_settings().consent

def get_pep_config() -> PEPConfig:
    return get_settings().pep

def get_causal_audit_config() -> CausalAuditConfig:
    return get_settings().causal_audit

def get_autopilot_config() -> AutopilotConfig:
    return get_settings().autopilot

def get_authzen_config() -> AuthZENConfig:
    return get_settings().authzen

def get_mesh_config() -> MeshConfig:
    return get_settings().mesh

def get_monitoring_config() -> MonitoringConfig:
    return get_settings().monitoring

def get_compliance_config() -> ComplianceConfig:
    return get_settings().compliance

def get_advanced_security_config() -> AdvancedSecurityConfig:
    return get_settings().advanced_security

def get_disaster_recovery_config() -> DisasterRecoveryConfig:
    return get_settings().disaster_recovery

def get_integration_test_config() -> IntegrationTestConfig:
    return get_settings().integration_test