/**
 * Security Enums and Type Constants
 */

export const Decision = {
  ALLOW: 'ALLOW',
  DENY: 'DENY',
  REQUIRE_APPROVAL: 'REQUIRE_APPROVAL'
};

export const BlastRadius = {
  LOW: 'LOW',         // Read-only on non-sensitive data
  MEDIUM: 'MEDIUM',   // Internal scoped modifications
  HIGH: 'HIGH',       // Outbound communication or external webhook
  CRITICAL: 'CRITICAL'// Sensitive credentials, banking details, system configuration
};

export const BlastRadiusExplanations = {
  LOW: 'Action is read-only and restricted to non-sensitive sandbox assets.',
  MEDIUM: 'Action alters internal non-critical state or performs scoped operations.',
  HIGH: 'Action triggers outbound external communication or data transmission outside the boundary.',
  CRITICAL: 'Action accesses high-privilege credentials, banking records, or system configuration.'
};

export const TaintLevel = {
  CLEAN: 'CLEAN',                     // Internal trusted source
  UNTRUSTED: 'UNTRUSTED_CONTENT',     // External document, email, web page
  POISONED: 'POISONED_INJECTION'      // Contains verified injection payload
};

export const AgentRoles = {
  REPORT_READER: 'report-reader', // Default least-privilege role
  SUPPORT: 'support',             // Support agent
  ADMIN: 'admin',                 // High-privilege role
  
  // Legacy aliases for backward compatibility
  SUPPORT_AGENT: 'SupportAgent',
  RESEARCH_AGENT: 'ResearchAgent',
  FINANCE_AGENT: 'FinanceAgent',
  ADMIN_AGENT: 'AdminAgent'
};

export const ToolSupplyStatus = {
  VERIFIED: 'VERIFIED',
  QUARANTINED: 'QUARANTINED',
  BLOCKED: 'BLOCKED'
};

export const RiskFactors = {
  INDIRECT_INJECTION: 'INDIRECT_PROMPT_INJECTION',
  UNAUTHORIZED_SECRET_ACCESS: 'UNAUTHORIZED_SECRET_ACCESS',
  UNRESTRICTED_EGRESS: 'UNRESTRICTED_EXTERNAL_EGRESS',
  POLICY_PERMISSION_MISMATCH: 'POLICY_PERMISSION_MISMATCH',
  HIGH_IMPACT_ACTION: 'HIGH_IMPACT_ACTION',
  TAINT_PROPAGATION: 'TAINT_PROPAGATION_DETECTED',
  TOOL_SHADOWING_DETECTED: 'TOOL_SHADOWING_DETECTED',
  TOOL_POISONING_DETECTED: 'TOOL_POISONING_DETECTED',
  LETHAL_TRIFECTA_DETECTED: 'LETHAL_TRIFECTA_DETECTED'
};
