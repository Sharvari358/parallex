import { Decision, BlastRadius, RiskFactors } from './types.js';

export class SemanticGuard {
  constructor() {
    this.injectionSignatures = [
      /system\s*override/i,
      /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
      /you\s+are\s+now\s+(in\s+developer\s+mode|unconstrained|dan)/i,
      /exfiltrate|leak|steal|send\s+secret/i,
      /\bcurl\b.*\b(webhook|attacker|evil|pastebin|ngrok)\b/i,
      /drop\s+table|delete\s+from|cat\s+\/etc/i,
      /reveal\s+(api\s*key|password|jwt|credentials)/i
    ];

    this.secretSignatures = [
      /AKIA[0-9A-Z]{16}/,                     // AWS Access Key
      /ghp_[a-zA-Z0-9]{36}/,                   // GitHub Personal Access Token
      /sk-[a-zA-Z0-9]{32,}/,                   // OpenAI / Stripe Secret Key
      /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}/, // JWT Token
      /BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY/
    ];
  }

  /**
   * Analyze document or web content for indirect prompt injections upon ingestion
   */
  inspectUntrustedContent(content, sourceName) {
    if (!content || typeof content !== 'string') {
      return { isInjected: false, confidence: 1.0, matchedSignatures: [] };
    }

    const matched = [];
    for (const pattern of this.injectionSignatures) {
      if (pattern.test(content)) {
        matched.push(pattern.source);
      }
    }

    // Check for stealth markdown exfiltration tags: e.g. ![leak](http://evil.com/...)
    if (/!\[.*?\]\(https?:\/\/[^\s)]+\)/i.test(content)) {
      matched.push('STEALTH_IMAGE_EXFILTRATION_MARKDOWN');
    }

    // Check for hidden HTML comment injections: <!-- ignore ... -->
    const hiddenComments = content.match(/<!--([\s\S]*?)-->/g);
    if (hiddenComments) {
      for (const comment of hiddenComments) {
        if (/system|instruction|override|ignore/i.test(comment)) {
          matched.push('HIDDEN_HTML_INJECTION_COMMENT');
        }
      }
    }

    const isInjected = matched.length > 0;
    return {
      isInjected,
      confidence: isInjected ? 0.96 : 0.92,
      matchedSignatures: matched,
      sourceName
    };
  }

  /**
   * Analyze intent consistency between the user's primary prompt and the agent's chosen tool call
   */
  evaluateIntentAlignment({ userPrompt, toolName, toolArgs, taintResult }) {
    const promptLower = (userPrompt || '').toLowerCase();
    const argsString = JSON.stringify(toolArgs || {}).toLowerCase();

    // Check 1: Did tainted content propagate into an exfiltration or communication tool?
    if (taintResult?.isTainted) {
      if (toolName === 'send_external_webhook' || taintResult.taintScore >= 0.9) {
        return {
          decision: Decision.DENY,
          reason: `Indirect Prompt Injection Alert: High-risk tainted data from '${taintResult.taintedSource}' was redirected into exfiltration channel '${toolName}'.`,
          ruleId: 'RULE-SEMANTIC-INJECTION-EXFILTRATION',
          blastRadius: BlastRadius.CRITICAL,
          confidence: 0.97,
          riskFactor: RiskFactors.INDIRECT_INJECTION
        };
      }

      if (toolName === 'send_email') {
        return {
          decision: Decision.REQUIRE_APPROVAL,
          reason: `Untrusted Origin Egress: Action requested from untrusted source '${taintResult.taintedSource}' involves high-blast communication '${toolName}'. Operator authorization required.`,
          ruleId: 'RULE-UNTRUSTED-HITL-REQUIRED',
          blastRadius: BlastRadius.HIGH,
          confidence: 0.95,
          riskFactor: RiskFactors.TAINT_PROPAGATION
        };
      }
    }

    // Check 2: Secret scanning in outgoing arguments
    for (const secretRegex of this.secretSignatures) {
      if (secretRegex.test(argsString)) {
        return {
          decision: Decision.DENY,
          reason: `Critical Data Exfiltration: Tool arguments contain high-entropy credential or API token signature (${secretRegex.source}). Blocked.`,
          ruleId: 'RULE-SECRET-LEAKAGE-BLOCKED',
          blastRadius: BlastRadius.CRITICAL,
          confidence: 0.99,
          riskFactor: RiskFactors.UNAUTHORIZED_SECRET_ACCESS
        };
      }
    }

    // Check 3: Semantic Intent Divergence
    // If user asked to "summarize" or "read", but agent suddenly calls an egress tool
    const isUserAskingToRead = /read|summarize|review|check|inspect|analyze|find/i.test(promptLower);
    const isUserAskingToTransmit = /send|email|post|webhook|transfer|forward|export/i.test(promptLower);

    if (isUserAskingToRead && !isUserAskingToTransmit && (toolName === 'send_external_webhook' || toolName === 'send_email')) {
      return {
        decision: Decision.DENY,
        reason: `Semantic Intent Divergence: User task is read-only ('${userPrompt}'), but agent attempted active external transmission ('${toolName}').`,
        ruleId: 'RULE-INTENT-DIVERGENCE-BLOCKED',
        blastRadius: BlastRadius.HIGH,
        confidence: 0.94,
        riskFactor: RiskFactors.INDIRECT_INJECTION
      };
    }

    return {
      decision: Decision.ALLOW,
      reason: 'Semantic intent aligned with user objective. No injection or exfiltration signatures detected.',
      ruleId: 'RULE-SEMANTIC-SAFE',
      blastRadius: BlastRadius.LOW,
      confidence: 0.92,
      riskFactor: null
    };
  }
}
