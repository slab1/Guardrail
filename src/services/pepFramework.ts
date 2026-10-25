// Guardrail PEP Framework (Policy Enforcement Points)
// pep-mcp, pep-fs (LSFS), pep-exec (Firecracker MicroVM), pep-net

import {
  AutonomyLevel,
  CATEGORY_REQUIRED_LEVEL,
  LSFSSnapshot,
  MicroVMState,
  NetworkRule,
  PEPRequest,
  PEPResponse,
  PEPType,
  TOOL_CATEGORY_MAP,
  ToolCategory,
} from "../types/guardrail";
import { defaultTokenService } from "./tokenService";

export class PepFramework {
  // Simulated File System Store for LSFS
  private fileSystem: Map<string, string> = new Map([
    ["/tmp/app_config.json", '{\n  "env": "production",\n  "database_url": "postgresql://db:5432/main"\n}'],
    ["/workspace/src/server.py", 'print("Starting server...")\n'],
    ["/workspace/README.md", "# Guardrail Protected Workspace\n"],
  ]);

  private snapshots: LSFSSnapshot[] = [];

  // Simulated MicroVM state
  private microVMs: MicroVMState[] = [
    {
      vm_id: "vm-fc-01",
      kernel_path: "/kernels/vmlinux-6.8-guardrail",
      vcpus: 2,
      memory_mb: 256,
      state: "idle",
      uptime_seconds: 1420,
    },
    {
      vm_id: "vm-fc-02",
      kernel_path: "/kernels/vmlinux-6.8-guardrail",
      vcpus: 1,
      memory_mb: 128,
      state: "idle",
      uptime_seconds: 830,
    },
  ];

  // Simulated Egress Network Rules
  private networkRules: NetworkRule[] = [
    {
      id: "net-01",
      pattern: "api.github.com",
      action: "ALLOW",
      tls_required: true,
      description: "GitHub API for repo access",
    },
    {
      id: "net-02",
      pattern: "registry.npmjs.org",
      action: "ALLOW",
      tls_required: true,
      description: "NPM Registry for packages",
    },
    {
      id: "net-03",
      pattern: "internal-payment.corp",
      action: "INJECT_SECRETS",
      tls_required: true,
      description: "Corp Payment Gateway (secrets injected by PEP)",
    },
    {
      id: "net-04",
      pattern: "*.*",
      action: "DENY",
      tls_required: false,
      description: "Default Deny all other outbound traffic",
    },
  ];

  // Enforcement Entry Point
  public async enforce(request: PEPRequest): Promise<PEPResponse> {
    const timestamp = Date.now();

    // 1. Verify Step Token if provided
    if (request.step_token) {
      const validation = await defaultTokenService.validateToken(
        request.step_token,
        request.plan_id || "",
        request.step_id,
        request.autonomy_level
      );

      if (!validation.valid) {
        return {
          pep_type: request.pep_type,
          allowed: false,
          status_code: 403,
          message: `Token Validation Failed: ${validation.reason}`,
          decision_reason: "Cryptographic step capability missing or expired",
          timestamp,
        };
      }
    }

    // Route to appropriate PEP
    switch (request.pep_type) {
      case PEPType.MCP:
        return this.enforceMcp(request, timestamp);
      case PEPType.FS:
        return this.enforceFs(request, timestamp);
      case PEPType.EXEC:
        return this.enforceExec(request, timestamp);
      case PEPType.NET:
        return this.enforceNet(request, timestamp);
      default:
        return {
          pep_type: request.pep_type,
          allowed: false,
          status_code: 400,
          message: "Unknown PEP type",
          decision_reason: "Unsupported actuator target",
          timestamp,
        };
    }
  }

  // --- PEP-MCP: Tool-level RBAC & Autonomy ladder ---
  private enforceMcp(request: PEPRequest, timestamp: number): PEPResponse {
    const toolName = request.action;
    const category: ToolCategory = TOOL_CATEGORY_MAP[toolName] || "admin";
    const requiredLevel = CATEGORY_REQUIRED_LEVEL[category];

    if (request.autonomy_level < requiredLevel) {
      return {
        pep_type: PEPType.MCP,
        allowed: false,
        status_code: 403,
        message: `Denied tool '${toolName}': category '${category}' requires autonomy level L${requiredLevel}`,
        decision_reason: `Agent autonomy L${request.autonomy_level} is insufficient for category '${category}'`,
        timestamp,
      };
    }

    // Parameter checks (e.g. rug-pull protection)
    if (toolName === "file_write" || toolName === "file_delete") {
      const path = request.resource;
      if (path.includes("..") || path.startsWith("/etc/") || path.startsWith("/sys/")) {
        return {
          pep_type: PEPType.MCP,
          allowed: false,
          status_code: 403,
          message: `Path traversal or sensitive root path blocked: ${path}`,
          decision_reason: "Host isolation boundary violation",
          timestamp,
        };
      }
    }

    return {
      pep_type: PEPType.MCP,
      allowed: true,
      status_code: 200,
      message: `Tool '${toolName}' permitted under Autonomy Level L${request.autonomy_level}`,
      decision_reason: `Category '${category}' within authorized bounds`,
      timestamp,
    };
  }

  // --- PEP-FS (LSFS Semantic Filesystem + Snapshot & Rollback) ---
  private enforceFs(request: PEPRequest, timestamp: number): PEPResponse {
    const filePath = request.resource;
    const action = request.action; // 'read', 'write', 'delete'

    if (action === "read") {
      const content = this.fileSystem.get(filePath) || "(file not found or empty)";
      return {
        pep_type: PEPType.FS,
        allowed: true,
        status_code: 200,
        message: `Read ${filePath} successfully (${content.length} bytes)`,
        decision_reason: "FS Read permitted for all autonomy levels",
        sanitized_payload: { content },
        timestamp,
      };
    }

    if (action === "write" || action === "delete") {
      if (request.autonomy_level < AutonomyLevel.L1) {
        return {
          pep_type: PEPType.FS,
          allowed: false,
          status_code: 403,
          message: `Write to ${filePath} blocked: L0 is read-only`,
          decision_reason: "Autonomy level L0 forbids filesystem mutations",
          timestamp,
        };
      }

      // Automatically create snapshot before mutation (LSFS pattern)
      const currentContent = this.fileSystem.get(filePath) || "";
      const snapshotId = `snap_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
      this.snapshots.push({
        snapshot_id: snapshotId,
        timestamp,
        path: filePath,
        original_content: currentContent,
        plan_id: request.plan_id || "adhoc",
        step_id: request.step_id || "step_0",
      });

      // Apply mutation
      if (action === "write") {
        const newContent = request.payload?.content || `Modified at ${new Date().toISOString()}`;
        this.fileSystem.set(filePath, newContent);
      } else if (action === "delete") {
        this.fileSystem.delete(filePath);
      }

      return {
        pep_type: PEPType.FS,
        allowed: true,
        status_code: 200,
        message: `Filesystem ${action} applied with rollback snapshot ${snapshotId}`,
        decision_reason: "LSFS snapshot committed, atomic mutation permitted",
        rollback_id: snapshotId,
        timestamp,
      };
    }

    return {
      pep_type: PEPType.FS,
      allowed: true,
      status_code: 200,
      message: `Action ${action} on ${filePath} approved`,
      decision_reason: "Allowed by FS policy",
      timestamp,
    };
  }

  // Instant Rollback capability
  public rollbackSnapshot(snapshotId: string): { success: boolean; message: string } {
    const snap = this.snapshots.find((s) => s.snapshot_id === snapshotId);
    if (!snap) {
      return { success: false, message: `Snapshot ${snapshotId} not found` };
    }
    this.fileSystem.set(snap.path, snap.original_content);
    return {
      success: true,
      message: `Rollback applied: ${snap.path} restored to state at ${new Date(snap.timestamp).toLocaleTimeString()}`,
    };
  }

  // --- PEP-EXEC: Firecracker MicroVM Isolation ---
  private enforceExec(request: PEPRequest, timestamp: number): PEPResponse {
    if (request.autonomy_level < AutonomyLevel.L2) {
      return {
        pep_type: PEPType.EXEC,
        allowed: false,
        status_code: 403,
        message: `Command execution blocked: requires at least L2 Semi-Autonomous`,
        decision_reason: "Execution requires L2/L3 autonomy",
        timestamp,
      };
    }

    const command = request.resource || "";

    // Command blacklist inspection
    if (command.includes("rm -rf /") || command.includes(":(){ :|:& };:") || command.includes("mkfs")) {
      return {
        pep_type: PEPType.EXEC,
        allowed: false,
        status_code: 403,
        message: "Catastrophic command blocked by Seccomp BPF filter",
        decision_reason: "Command matches catastrophic denial heuristic",
        timestamp,
      };
    }

    // Allocate an idle VM
    const vm = this.microVMs[0];
    vm.state = "running";
    vm.active_execution = command;

    setTimeout(() => {
      vm.state = "idle";
      vm.active_execution = undefined;
    }, 2000);

    return {
      pep_type: PEPType.EXEC,
      allowed: true,
      status_code: 200,
      message: `Executed in Firecracker microVM [${vm.vm_id}] with 256MB cgroup limit`,
      decision_reason: "Hardware-isolated microVM instance allocated",
      sanitized_payload: {
        vm_id: vm.vm_id,
        exit_code: 0,
        stdout: `[${vm.vm_id}] Simulated execution of: ${command}`,
      },
      timestamp,
    };
  }

  // --- PEP-NET: Egress Network Gateway ---
  private enforceNet(request: PEPRequest, timestamp: number): PEPResponse {
    const targetUrl = request.resource;
    let domain = targetUrl;
    try {
      if (targetUrl.startsWith("http")) {
        domain = new URL(targetUrl).hostname;
      }
    } catch {
      domain = targetUrl;
    }

    // Find matching rule
    const matchingRule = this.networkRules.find((rule) => {
      if (rule.pattern === "*.*") return true;
      if (rule.pattern === domain) return true;
      if (rule.pattern.startsWith("*.") && domain.endsWith(rule.pattern.slice(2))) return true;
      return false;
    });

    if (!matchingRule || matchingRule.action === "DENY") {
      return {
        pep_type: PEPType.NET,
        allowed: false,
        status_code: 403,
        message: `Outbound connection to '${domain}' rejected by PEP-Net Egress Policy`,
        decision_reason: "Host not in corporate egress allowlist",
        timestamp,
      };
    }

    if (matchingRule.action === "INJECT_SECRETS") {
      return {
        pep_type: PEPType.NET,
        allowed: true,
        status_code: 200,
        message: `Outbound connection to '${domain}' permitted with PEP secret injection`,
        decision_reason: "Agent credential masked: proxy injected signed Bearer token",
        sanitized_payload: { masked_headers: { Authorization: "Bearer [INJECTED_BY_PEP]" } },
        timestamp,
      };
    }

    return {
      pep_type: PEPType.NET,
      allowed: true,
      status_code: 200,
      message: `Outbound connection to '${domain}' allowed`,
      decision_reason: `Matched allow rule: ${matchingRule.description}`,
      timestamp,
    };
  }

  // Public inspectors
  public getFileSystem(): Record<string, string> {
    const obj: Record<string, string> = {};
    this.fileSystem.forEach((val, key) => (obj[key] = val));
    return obj;
  }

  public getSnapshots(): LSFSSnapshot[] {
    return [...this.snapshots];
  }

  public getMicroVMs(): MicroVMState[] {
    return [...this.microVMs];
  }

  public getNetworkRules(): NetworkRule[] {
    return [...this.networkRules];
  }

  public addNetworkRule(rule: NetworkRule): void {
    this.networkRules.unshift(rule);
  }
}

export const defaultPepFramework = new PepFramework();
