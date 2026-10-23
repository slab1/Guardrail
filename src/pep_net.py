"""PEP-Net: Policy Enforcement Point for Network Egress Policy."""
import socket
import ssl
import urllib.request
import urllib.parse
import json
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from pep_framework import BasePEP, PEPRequest, PEPResponse, PEPType, register_pep


class NetworkAction(Enum):
    """Types of network actions."""
    HTTP_GET = "http_get"
    HTTP_POST = "http_post"
    HTTP_PUT = "http_put"
    HTTP_DELETE = "http_delete"
    TCP_CONNECT = "tcp_connect"
    UDP_SEND = "udp_send"
    DNS_RESOLVE = "dns_resolve"


@dataclass
class NetworkRule:
    """Network egress rule."""
    name: str
    action: NetworkAction
    allowed_domains: List[str] = field(default_factory=list)  # Domain patterns (e.g., "*.example.com")
    allowed_ips: List[str] = field(default_factory=list)       # CIDR notation
    allowed_ports: List[int] = field(default_factory=list)
    allowed_protocols: List[str] = field(default_factory=lambda: ["http", "https"])
    max_payload_size: int = 10 * 1024 * 1024  # 10MB default
    require_tls: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkRequest:
    """Parsed network request details."""
    action: NetworkAction
    url: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    path: str = "/"
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    query_params: Dict[str, str] = field(default_factory=dict)


class NetworkPolicyEngine:
    """Evaluates network requests against policies."""
    
    def __init__(self):
        self.rules: List[NetworkRule] = []
        self.default_deny = True
    
    def add_rule(self, rule: NetworkRule):
        """Add a network rule."""
        self.rules.append(rule)
    
    def remove_rule(self, rule_name: str):
        """Remove a rule by name."""
        self.rules = [r for r in self.rules if r.name != rule_name]
    
    def _match_domain(self, domain: str, patterns: List[str]) -> bool:
        """Match domain against patterns (supports wildcards)."""
        for pattern in patterns:
            if pattern == "*":
                return True
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if domain.endswith(suffix) or domain == suffix[1:]:
                    return True
            if domain == pattern:
                return True
        return False
    
    def _match_ip(self, ip: str, cidrs: List[str]) -> bool:
        """Match IP against CIDR ranges."""
        import ipaddress
        try:
            ip_addr = ipaddress.ip_address(ip)
            for cidr in cidrs:
                if ip_addr in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            pass
        return False
    
    def evaluate(self, request: NetworkRequest) -> tuple:
        """Evaluate a network request against rules.
        
        Returns:
            (allowed: bool, rule_name: str, reason: str)
        """
        # Try to resolve host to IP for IP-based rules
        resolved_ip = None
        if request.host:
            try:
                resolved_ip = socket.gethostbyname(request.host)
            except socket.gaierror:
                pass
        
        for rule in self.rules:
            if rule.action != request.action:
                continue
            
            # Check domain
            if rule.allowed_domains and request.host:
                if not self._match_domain(request.host, rule.allowed_domains):
                    continue
            
            # Check IP
            if rule.allowed_ips and resolved_ip:
                if not self._match_ip(resolved_ip, rule.allowed_ips):
                    continue
            
            # Check port
            if rule.allowed_ports and request.port:
                if request.port not in rule.allowed_ports:
                    continue
            
            # Check protocol (for HTTP)
            if request.action in (NetworkAction.HTTP_GET, NetworkAction.HTTP_POST,
                                 NetworkAction.HTTP_PUT, NetworkAction.HTTP_DELETE):
                protocol = "https" if request.url and request.url.startswith("https") else "http"
                if protocol not in rule.allowed_protocols:
                    continue
            
            # Check payload size
            if request.body and len(request.body) > rule.max_payload_size:
                continue
            
            # Check TLS requirement
            if rule.require_tls and request.url and not request.url.startswith("https"):
                continue
            
            # All checks passed
            return (True, rule.name, "Allowed by policy")
        
        return (False, "default", "Denied by default policy" if self.default_deny else "No matching rule")


class NetworkExecutor:
    """Executes network requests through the policy engine."""
    
    def __init__(self, policy_engine: NetworkPolicyEngine):
        self.policy_engine = policy_engine
    
    def _parse_request(self, request: PEPRequest) -> NetworkRequest:
        """Parse PEPRequest into NetworkRequest."""
        action = NetworkAction(request.action)
        metadata = request.metadata
        
        return NetworkRequest(
            action=action,
            url=metadata.get("url"),
            host=metadata.get("host"),
            port=metadata.get("port"),
            path=metadata.get("path", "/"),
            method=metadata.get("method", "GET"),
            headers=metadata.get("headers", {}),
            body=metadata.get("body"),
            query_params=metadata.get("query_params", {}),
        )
    
    def _execute_http(self, net_request: NetworkRequest) -> PEPResponse:
        """Execute an HTTP request."""
        if not net_request.url:
            return PEPResponse(
                success=False,
                error="URL required for HTTP requests"
            )
        
        # Prepare request
        req = urllib.request.Request(
            net_request.url,
            data=net_request.body,
            method=net_request.method,
            headers=net_request.headers
        )
        
        # Execute
        start_time = time.time()
        try:
            context = ssl.create_default_context()
            with urllib.request.urlopen(req, context=context, timeout=30) as response:
                content = response.read()
                duration_ms = int((time.time() - start_time) * 1000)
                
                return PEPResponse(
                    success=True,
                    result={
                        "status_code": response.status,
                        "headers": dict(response.headers),
                        "body": content,
                        "duration_ms": duration_ms,
                    }
                )
        except urllib.error.HTTPError as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return PEPResponse(
                success=False,
                error=f"HTTP {e.code}: {e.reason}",
                details={"status_code": e.code, "duration_ms": duration_ms}
            )
        except Exception as e:
            return PEPResponse(
                success=False,
                error=f"Network error: {str(e)}"
            )
    
    def _execute_tcp(self, net_request: NetworkRequest) -> PEPResponse:
        """Execute a TCP connection."""
        if not net_request.host or not net_request.port:
            return PEPResponse(
                success=False,
                error="Host and port required for TCP"
            )
        
        start_time = time.time()
        try:
            sock = socket.create_connection(
                (net_request.host, net_request.port),
                timeout=10
            )
            sock.close()
            duration_ms = int((time.time() - start_time) * 1000)
            
            return PEPResponse(
                success=True,
                result={"connected": True, "duration_ms": duration_ms}
            )
        except Exception as e:
            return PEPResponse(
                success=False,
                error=f"TCP connection failed: {str(e)}"
            )
    
    def _execute_dns(self, net_request: NetworkRequest) -> PEPResponse:
        """Execute DNS resolution."""
        if not net_request.host:
            return PEPResponse(
                success=False,
                error="Host required for DNS resolution"
            )
        
        try:
            ips = socket.gethostbyname_ex(net_request.host)[2]
            return PEPResponse(
                success=True,
                result={"host": net_request.host, "ips": ips}
            )
        except Exception as e:
            return PEPResponse(
                success=False,
                error=f"DNS resolution failed: {str(e)}"
            )
    
    def execute(self, request: PEPRequest) -> PEPResponse:
        """Execute a network request after policy check."""
        net_request = self._parse_request(request)
        
        # Policy evaluation
        allowed, rule_name, reason = self.policy_engine.evaluate(net_request)
        
        if not allowed:
            return PEPResponse(
                success=False,
                error=f"Network policy denied: {reason}",
                details={"rule": rule_name, "action": request.action, "resource": request.resource}
            )
        
        # Execute based on action
        try:
            if request.action in ("http_get", "http_post", "http_put", "http_delete"):
                return self._execute_http(net_request)
            elif request.action == "tcp_connect":
                return self._execute_tcp(net_request)
            elif request.action == "dns_resolve":
                return self._execute_dns(net_request)
            else:
                return PEPResponse(
                    success=False,
                    error=f"Unsupported network action: {request.action}"
                )
        except Exception as e:
            return PEPResponse(
                success=False,
                error=f"Execution error: {str(e)}"
            )


class PepNet(BasePEP):
    """PEP-Net: Policy Enforcement Point for Network Egress."""
    
    def __init__(self, policy_engine: Optional[NetworkPolicyEngine] = None):
        super().__init__(PEPType.NET)
        self.policy_engine = policy_engine or NetworkPolicyEngine()
        self.executor = NetworkExecutor(self.policy_engine)
        
        # Define allowed actions
        self.allowed_actions = {
            "http_get", "http_post", "http_put", "http_delete",
            "tcp_connect", "udp_send", "dns_resolve",
        }
        self.action_categories = {
            "http_get": "read",
            "http_post": "write",
            "http_put": "write",
            "http_delete": "write",
            "tcp_connect": "execute",
            "udp_send": "execute",
            "dns_resolve": "read",
        }
        
        # Add default rules for common scenarios
        self._add_default_rules()
    
    def _add_default_rules(self):
        """Add default network rules."""
        # Allow HTTPS to common API domains
        self.policy_engine.add_rule(NetworkRule(
            name="allow_https_apis",
            action=NetworkAction.HTTP_GET,
            allowed_domains=["api.github.com", "api.openai.com", "api.anthropic.com", "*.amazonaws.com"],
            allowed_ports=[443],
            allowed_protocols=["https"],
            require_tls=True,
        ))
        self.policy_engine.add_rule(NetworkRule(
            name="allow_https_apis_post",
            action=NetworkAction.HTTP_POST,
            allowed_domains=["api.github.com", "api.openai.com", "api.anthropic.com", "*.amazonaws.com"],
            allowed_ports=[443],
            allowed_protocols=["https"],
            require_tls=True,
        ))
        
        # Allow DNS resolution
        self.policy_engine.add_rule(NetworkRule(
            name="allow_dns",
            action=NetworkAction.DNS_RESOLVE,
            allowed_domains=["*"],
        ))
        
        # Allow local connections
        self.policy_engine.add_rule(NetworkRule(
            name="allow_localhost",
            action=NetworkAction.TCP_CONNECT,
            allowed_ips=["127.0.0.1/32", "::1/128"],
            allowed_ports=list(range(1024, 65535)),
        ))
    
    def add_rule(self, rule: NetworkRule):
        """Add a custom network rule."""
        self.policy_engine.add_rule(rule)
    
    def enforce(self, request: PEPRequest) -> PEPResponse:
        """Enforce network egress policy."""
        # Validate token
        if not self.validate_token(request):
            return self.create_denied_response(request, "Invalid or expired token")
        
        # Check if action is allowed
        if not self.check_action_allowed(request.action):
            return self.create_denied_response(request, f"Action not allowed: {request.action}")
        
        # Execute through policy engine
        return self.executor.execute(request)


# Convenience function
def create_pep_net() -> PepNet:
    """Create and register a PepNet instance."""
    pep_net = PepNet()
    register_pep(pep_net)
    return pep_net


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    pep_net = create_pep_net()
    
    from token_service import create_step_token
    
    token = create_step_token("plan_001", "step_001", "HTTP GET to GitHub API", "coding", "user1", 1)
    
    # Test allowed request
    request = PEPRequest(
        pep_type=PEPType.NET,
        token=token,
        plan_id="plan_001",
        step_id="step_001",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
        action="http_get",
        resource="https://api.github.com/users/octocat",
        metadata={
            "url": "https://api.github.com/users/octocat",
            "host": "api.github.com",
            "port": 443,
            "method": "GET",
        }
    )
    
    response = pep_net.enforce(request)
    print(f"HTTP GET to GitHub API: {response.success}")
    if response.success:
        print(f"  Status: {response.result.get('status_code')}")
    else:
        print(f"  Error: {response.error}")
    
    # Test denied request (non-HTTPS)
    request2 = PEPRequest(
        pep_type=PEPType.NET,
        token=token,
        plan_id="plan_001",
        step_id="step_002",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
        action="http_get",
        resource="http://example.com",
        metadata={
            "url": "http://example.com",
            "host": "example.com",
            "port": 80,
            "method": "GET",
        }
    )
    
    response2 = pep_net.enforce(request2)
    print(f"HTTP GET to HTTP (non-TLS): {response2.success}")
    if not response2.success:
        print(f"  Error: {response2.error}")