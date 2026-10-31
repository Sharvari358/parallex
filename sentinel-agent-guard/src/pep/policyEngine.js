import { Decision, BlastRadius, BlastRadiusExplanations, AgentRoles, RiskFactors } from './types.js';

export class PolicyEngine {
  constructor() {
    this.policies = this.getDefaultPolicies();
    this.protectedResources = [
      'bank_details.txt',
      'DATABASE_PASSWORD',
      '/etc/shadow'
    ];
    this.allowedEgressDestinations = [
      'company.com',
      'internal-service.local',
      'api.internal-service.local',
      'hooks.slack.com'
    ];
  }

  normalizeRole(role) {
    if (!role) return AgentRoles.REPORT_READER;
    const r = role.toLowerCase().trim();
    if (r === 'admin' || r === 'adminagent') return AgentRoles.ADMIN;
    if (r === 'support' || r === 'supportagent') return AgentRoles.SUPPORT;
    if (r === 'report-reader' || r === 'reportreader' || r === 'researchagent') return AgentRoles.REPORT_READER;
    return role;
  }

  getDefaultPolicies() {
    return {
      tools: {
        read_document: {
          allowedRoles: [AgentRoles.REPORT_READER, AgentRoles.SUPPORT, AgentRoles.ADMIN],
          blastRadius: BlastRadius.LOW,
          defaultDecision: Decision.ALLOW,
          permission: 'filesystem:read:document',
          restrictions: {
            disallowedPatterns: [/\.env$/i, /id_rsa/i, /\/etc\//i, /credentials\.json/i],
            // report-reader can ONLY read reports or tickets
            reportReaderAllowedPrefixes: ['reports/', 'ticket_', 'quarterly_report']
          }
        },
        read_system_secrets: {
          allowedRoles: [AgentRoles.ADMIN], // Strictly admin only!
          blastRadius: BlastRadius.CRITICAL,
          defaultDecision: Decision.DENY,
          permission: 'vault:read:secret',
          reason: 'Access to system credentials vault requires Admin role'
        },
        send_external_webhook: {
          allowedRoles: [AgentRoles.ADMIN],
          blastRadius: BlastRadius.HIGH,
          defaultDecision: Decision.REQUIRE_APPROVAL,
          permission: 'network:egress:webhook',
          restrictions: {
            allowedDomains: ['api.internal-service.local', 'hooks.slack.com']
          }
        },
        send_email: {
          allowedRoles: [AgentRoles.SUPPORT, AgentRoles.ADMIN], // report-reader cannot send emails!
          blastRadius: BlastRadius.HIGH,
          defaultDecision: Decision.REQUIRE_APPROVAL,
          permission: 'communication:egress:email',
          requiresHumanApproval: true
        },
        delete_file: {
          allowedRoles: [AgentRoles.ADMIN], // report-reader & support cannot delete!
          blastRadius: BlastRadius.CRITICAL,
          defaultDecision: Decision.DENY,
          permission: 'filesystem:write:delete',
          reason: 'Destructive file deletion is restricted to Admin role'
        }
      }
    };
  }

  /**
   * Evaluate static and RBAC policy rules against a requested tool invocation
   */
  evaluate({ agentRole, toolName, toolArgs, isTainted = false }) {
    const role = this.normalizeRole(agentRole);
    const toolPolicy = this.policies.tools[toolName];

    // Check 1: Tool Existence & Registration
    if (!toolPolicy) {
      return {
        decision: Decision.DENY,
        reason: `Tool '${toolName}' is not registered in the security policy schema.`,
        ruleId: 'RULE-TOOL-NOT-REGISTERED',
        blastRadius: BlastRadius.HIGH,
        blastExplanation: BlastRadiusExplanations.HIGH,
        confidence: 1.0,
        riskFactor: RiskFactors.POLICY_PERMISSION_MISMATCH,
        isProtectedResource: false,
        destination: null
      };
    }

    // Check 2: Protected Resources Defense
    const resourceId = toolArgs?.doc_id || toolArgs?.key_name || toolArgs?.path || '';
    const isProtected = this.protectedResources.some(pr => 
      resourceId.toLowerCase().includes(pr.toLowerCase())
    );

    if (isProtected) {
      // bank_details.txt, DATABASE_PASSWORD, and /etc/shadow can ONLY be accessed by admin
      if (role !== AgentRoles.ADMIN) {
        return {
          decision: Decision.DENY,
          reason: `Access Denied: Resource '${resourceId}' is classified as a PROTECTED SENSITIVE RESOURCE. Role '${role}' lacks explicit administrative clearance.`,
          ruleId: 'RULE-PROTECTED-RESOURCE-DENIED',
          blastRadius: BlastRadius.CRITICAL,
          blastExplanation: BlastRadiusExplanations.CRITICAL,
          confidence: 1.0,
          riskFactor: RiskFactors.UNAUTHORIZED_SECRET_ACCESS,
          isProtectedResource: true,
          destination: null,
          permission: toolPolicy.permission
        };
      }
    }

    // Check 3: Role-Based Access Control (RBAC) Least Privilege
    if (!toolPolicy.allowedRoles.includes(role)) {
      return {
        decision: Decision.DENY,
        reason: `RBAC Violation: Role '${role}' lacks permission '${toolPolicy.permission}' for tool '${toolName}'. Permitted roles: [${toolPolicy.allowedRoles.join(', ')}].`,
        ruleId: 'RULE-RBAC-VIOLATION',
        blastRadius: toolPolicy.blastRadius,
        blastExplanation: BlastRadiusExplanations[toolPolicy.blastRadius],
        confidence: 1.0,
        riskFactor: RiskFactors.POLICY_PERMISSION_MISMATCH,
        isProtectedResource: isProtected,
        destination: null,
        permission: toolPolicy.permission
      };
    }

    // Check 4: report-reader Scope Enforcement (can only read reports/tickets, no bank/financial files)
    if (role === AgentRoles.REPORT_READER && toolName === 'read_document') {
      const docId = String(toolArgs?.doc_id || '').toLowerCase();
      
      // Specifically block bank or financial documents
      if (docId.includes('bank') || docId.includes('financial_ledger') || docId.includes('payroll')) {
        return {
          decision: Decision.DENY,
          reason: `Scope Violation: Role 'report-reader' is strictly prohibited from accessing banking, financial, or ledger files ('${docId}').`,
          ruleId: 'RULE-REPORT-READER-FINANCIAL-BLOCKED',
          blastRadius: BlastRadius.HIGH,
          blastExplanation: BlastRadiusExplanations.HIGH,
          confidence: 1.0,
          riskFactor: RiskFactors.POLICY_PERMISSION_MISMATCH,
          isProtectedResource: true,
          destination: null,
          permission: toolPolicy.permission
        };
      }
    }

    // Check 5: Path Sandbox Traversal Patterns
    if (toolName === 'read_document' && toolArgs?.doc_id) {
      const docPath = String(toolArgs.doc_id);
      for (const pattern of toolPolicy.restrictions.disallowedPatterns) {
        if (pattern.test(docPath)) {
          return {
            decision: Decision.DENY,
            reason: `Access to restricted path or sensitive system file '${docPath}' is forbidden by path sandbox policy.`,
            ruleId: 'RULE-RESTRICTED-PATH-ACCESS',
            blastRadius: BlastRadius.CRITICAL,
            blastExplanation: BlastRadiusExplanations.CRITICAL,
            confidence: 1.0,
            riskFactor: RiskFactors.UNAUTHORIZED_SECRET_ACCESS,
            isProtectedResource: true,
            destination: null,
            permission: toolPolicy.permission
          };
        }
      }
    }

    // Check 6: Egress (Destination) Control
    let destination = null;
    if (toolName === 'send_external_webhook' && toolArgs?.url) {
      destination = toolArgs.url;
      try {
        const targetUrl = new URL(toolArgs.url);
        const host = targetUrl.hostname;
        const isWhitelisted = this.allowedEgressDestinations.some(d => host === d || host.endsWith('.' + d));
        
        if (!isWhitelisted) {
          return {
            decision: Decision.DENY,
            reason: `Egress Blocked: Destination '${host}' is not on the approved destination allowlist. Outbound network transmission denied.`,
            ruleId: 'RULE-EGRESS-DESTINATION-UNAUTHORIZED',
            blastRadius: BlastRadius.HIGH,
            blastExplanation: `Destination '${host}' is unapproved. External communication denied.`,
            confidence: 1.0,
            riskFactor: RiskFactors.UNRESTRICTED_EGRESS,
            isProtectedResource: isProtected,
            destination,
            permission: toolPolicy.permission
          };
        }
      } catch (e) {
        return {
          decision: Decision.DENY,
          reason: `Malformed destination URL: '${toolArgs.url}'.`,
          ruleId: 'RULE-MALFORMED-EGRESS-URL',
          blastRadius: BlastRadius.MEDIUM,
          blastExplanation: BlastRadiusExplanations.MEDIUM,
          confidence: 1.0,
          riskFactor: RiskFactors.POLICY_PERMISSION_MISMATCH,
          isProtectedResource: isProtected,
          destination: toolArgs.url,
          permission: toolPolicy.permission
        };
      }
    }

    if (toolName === 'send_email' && toolArgs?.to) {
      destination = toolArgs.to;
      const emailDomain = toolArgs.to.split('@')[1] || '';
      const isApprovedDomain = this.allowedEgressDestinations.some(d => 
        emailDomain === d || emailDomain.endsWith('.' + d)
      );

      // If destination is not on the allowlist and content is tainted -> DENY
      if (!isApprovedDomain && isTainted) {
        return {
          decision: Decision.DENY,
          reason: `Egress Blocked: Email destination '${toolArgs.to}' is not on the company allowlist and payload contains tainted content.`,
          ruleId: 'RULE-UNAPPROVED-DESTINATION-TAINTED',
          blastRadius: BlastRadius.HIGH,
          blastExplanation: `Recipient '${toolArgs.to}' is external/unapproved and payload is tainted.`,
          confidence: 0.98,
          riskFactor: RiskFactors.UNRESTRICTED_EGRESS,
          isProtectedResource: isProtected,
          destination,
          permission: toolPolicy.permission
        };
      }

      // If destination is unapproved but content is untainted -> REQUIRE_APPROVAL
      if (!isApprovedDomain) {
        return {
          decision: Decision.REQUIRE_APPROVAL,
          reason: `Outbound Egress: Recipient '${toolArgs.to}' is external (not in company allowlist). Operator authorization required.`,
          ruleId: 'RULE-EXTERNAL-RECIPIENT-APPROVAL',
          blastRadius: BlastRadius.HIGH,
          blastExplanation: `Outbound email to external recipient '${toolArgs.to}' requires human sign-off.`,
          confidence: 0.95,
          riskFactor: RiskFactors.HIGH_IMPACT_ACTION,
          isProtectedResource: isProtected,
          destination,
          permission: toolPolicy.permission
        };
      }
    }

    // Check 7: Standard High-Impact Action Requiring Human-In-The-Loop Approval
    if (toolPolicy.requiresHumanApproval) {
      return {
        decision: Decision.REQUIRE_APPROVAL,
        reason: `High-Impact Action: Tool '${toolName}' performs an external communication or state alteration. Operator confirmation required.`,
        ruleId: 'RULE-HITL-CONFIRMATION-REQUIRED',
        blastRadius: toolPolicy.blastRadius,
        blastExplanation: BlastRadiusExplanations[toolPolicy.blastRadius],
        confidence: 1.0,
        riskFactor: RiskFactors.HIGH_IMPACT_ACTION,
        isProtectedResource: isProtected,
        destination,
        permission: toolPolicy.permission
      };
    }

    // Default policy decision: ALLOW
    return {
      decision: toolPolicy.defaultDecision,
      reason: `Tool '${toolName}' conforms to least-privilege permission profile '${toolPolicy.permission}' for role '${role}'.`,
      ruleId: 'RULE-STANDARD-ALLOW',
      blastRadius: toolPolicy.blastRadius,
      blastExplanation: BlastRadiusExplanations[toolPolicy.blastRadius],
      confidence: 0.95,
      riskFactor: null,
      isProtectedResource: isProtected,
      destination,
      permission: toolPolicy.permission
    };
  }
}
