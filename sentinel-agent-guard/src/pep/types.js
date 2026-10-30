/**
 * Security Enums and Type Constants
 */

export const Decision = {
  ALLOW: 'ALLOW',
  DENY: 'DENY',
  REQUIRE_APPROVAL: 'REQUIRE_APPROVAL'
};

export const BlastRadius = {
  LOW: 'LOW',         // Read-only on public or non-sensitive data
  MEDIUM: 'MEDIUM',   // Internal state changes, scoped writes
  HIGH: 'HIGH',       // External communications (email, public webhooks), sensitive record updates
  CRITICAL: 'CRITICAL'// Secret vaults, database drop, credentials access
};

export const TaintLevel = {
  CLEAN: 'CLEAN',                     // Internal trusted source
  UNTRUSTED: 'UNTRUSTED_CONTENT',     // External document, email, web page
  POISONED: 'POISONED_INJECTION'      // Contains verified injection payload
};

export const AgentRoles = {
  SUPPORT_AGENT: 'SupportAgent',
  RESEARCH_AGENT: 'ResearchAgent',
  FINANCE_AGENT: 'FinanceAgent',
  ADMIN_AGENT: 'AdminAgent'
};

export const RiskFactors = {
  INDIRECT_INJECTION: 'INDIRECT_PROMPT_INJECTION',
  UNAUTHORIZED_SECRET_ACCESS: 'UNAUTHORIZED_SECRET_ACCESS',
  UNRESTRICTED_EGRESS: 'UNRESTRICTED_EXTERNAL_EGRESS',
  POLICY_PERMISSION_MISMATCH: 'POLICY_PERMISSION_MISMATCH',
  HIGH_IMPACT_ACTION: 'HIGH_IMPACT_ACTION',
  TAINT_PROPAGATION: 'TAINT_PROPAGATION_DETECTED'
};
