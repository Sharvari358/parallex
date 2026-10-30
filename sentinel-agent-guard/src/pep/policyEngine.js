import { Decision, BlastRadius, AgentRoles, RiskFactors } from './types.js';

export class PolicyEngine {
  constructor() {
    this.policies = this.getDefaultPolicies();
  }

  getDefaultPolicies() {
    return {
      tools: {
        read_document: {
          allowedRoles: [AgentRoles.SUPPORT_AGENT, AgentRoles.RESEARCH_AGENT, AgentRoles.ADMIN_AGENT],
          blastRadius: BlastRadius.LOW,
          defaultDecision: Decision.ALLOW,
          restrictions: {
            disallowedPatterns: [/\.env$/i, /id_rsa/i, /\/etc\//i, /credentials\.json/i]
          }
        },
        read_system_secrets: {
          allowedRoles: [AgentRoles.ADMIN_AGENT], // SupportAgent cannot access secrets!
          blastRadius: BlastRadius.CRITICAL,
          defaultDecision: Decision.DENY,
          reason: 'Access to system credentials vault requires AdminAgent role'
        },
        send_external_webhook: {
          allowedRoles: [AgentRoles.ADMIN_AGENT],
          blastRadius: BlastRadius.HIGH,
          defaultDecision: Decision.REQUIRE_APPROVAL,
          restrictions: {
            allowedDomains: ['api.internal-service.local', 'hooks.slack.com/services/internal']
          }
        },
        send_email: {
          allowedRoles: [AgentRoles.SUPPORT_AGENT, AgentRoles.ADMIN_AGENT],
          blastRadius: BlastRadius.HIGH,
          defaultDecision: Decision.REQUIRE_APPROVAL, // High-impact action requires human confirmation
          requiresHumanApproval: true
        }
      }
    };
  }

  /**
   * Evaluate static and RBAC policy rules against a requested tool invocation
   */
  evaluate({ agentRole, toolName, toolArgs }) {
    const toolPolicy = this.policies.tools[toolName];

    // Check 1: Tool Existence & Registration
    if (!toolPolicy) {
      return {
        decision: Decision.DENY,
        reason: `Tool '${toolName}' is not registered in the security policy schema.`,
        ruleId: 'RULE-TOOL-NOT-REGISTERED',
        blastRadius: BlastRadius.HIGH,
        confidence: 1.0,
        riskFactor: RiskFactors.POLICY_PERMISSION_MISMATCH
      };
    }

    // Check 2: Role-Based Access Control (RBAC)
    if (!toolPolicy.allowedRoles.includes(agentRole)) {
      return {
        decision: Decision.DENY,
        reason: `Role '${agentRole}' is unauthorized to invoke '${toolName}'. Requires one of [${toolPolicy.allowedRoles.join(', ')}].`,
        ruleId: 'RULE-RBAC-VIOLATION',
        blastRadius: toolPolicy.blastRadius,
        confidence: 1.0,
        riskFactor: RiskFactors.UNAUTHORIZED_SECRET_ACCESS
      };
    }

    // Check 3: Path / Parameter Restrictions (e.g. attempting to read .env file via document reader)
    if (toolName === 'read_document' && toolArgs?.doc_id) {
      const docPath = String(toolArgs.doc_id);
      for (const pattern of toolPolicy.restrictions.disallowedPatterns) {
        if (pattern.test(docPath)) {
          return {
            decision: Decision.DENY,
            reason: `Access to restricted path or sensitive system file '${docPath}' is forbidden by path sandbox policy.`,
            ruleId: 'RULE-RESTRICTED-PATH-ACCESS',
            blastRadius: BlastRadius.CRITICAL,
            confidence: 1.0,
            riskFactor: RiskFactors.UNAUTHORIZED_SECRET_ACCESS
          };
        }
      }
    }

    // Check 4: Domain Whitelist Restrictions for Webhooks/Egress
    if (toolName === 'send_external_webhook' && toolArgs?.url) {
      try {
        const targetUrl = new URL(toolArgs.url);
        const isWhitelisted = toolPolicy.restrictions.allowedDomains.some(domain => 
          targetUrl.hostname === domain || targetUrl.hostname.endsWith('.' + domain)
        );
        if (!isWhitelisted) {
          return {
            decision: Decision.DENY,
            reason: `Outbound egress to unauthorized destination '${targetUrl.hostname}' is prohibited. Destination not in approved domain whitelist.`,
            ruleId: 'RULE-EGRESS-DOMAIN-NOT-WHITELISTED',
            blastRadius: BlastRadius.HIGH,
            confidence: 0.98,
            riskFactor: RiskFactors.UNRESTRICTED_EGRESS
          };
        }
      } catch (err) {
        return {
          decision: Decision.DENY,
          reason: `Invalid or malformed URL in webhook request: '${toolArgs.url}'.`,
          ruleId: 'RULE-MALFORMED-EGRESS-URL',
          blastRadius: BlastRadius.MEDIUM,
          confidence: 1.0,
          riskFactor: RiskFactors.POLICY_PERMISSION_MISMATCH
        };
      }
    }

    // Check 5: High-Impact Action Requiring Human-In-The-Loop Approval
    if (toolPolicy.requiresHumanApproval) {
      return {
        decision: Decision.REQUIRE_APPROVAL,
        reason: `Tool '${toolName}' performs an external communication or state alteration with '${toolPolicy.blastRadius}' impact. Operator confirmation required.`,
        ruleId: 'RULE-HITL-CONFIRMATION-REQUIRED',
        blastRadius: toolPolicy.blastRadius,
        confidence: 1.0,
        riskFactor: RiskFactors.HIGH_IMPACT_ACTION
      };
    }

    // Default policy decision
    return {
      decision: toolPolicy.defaultDecision,
      reason: `Tool '${toolName}' conforms to standard permission profile for role '${agentRole}'.`,
      ruleId: 'RULE-STANDARD-ALLOW',
      blastRadius: toolPolicy.blastRadius,
      confidence: 0.95,
      riskFactor: null
    };
  }
}
