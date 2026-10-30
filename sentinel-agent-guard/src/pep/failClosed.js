import { Decision, BlastRadius } from './types.js';
import { CONFIG } from '../config.js';

export class FailClosedArbiter {
  /**
   * Enforces fail-closed semantics across all evaluation outputs
   */
  static arbitrate(evaluations, error = null) {
    // 1. If an error occurred in any security evaluator, fail-closed immediately
    if (error) {
      return {
        decision: Decision.DENY,
        reason: `Fail-Closed Security Override: An internal evaluation exception occurred (${error.message}). Action blocked by safety boundary.`,
        ruleId: 'RULE-FAIL-CLOSED-EXCEPTION',
        blastRadius: BlastRadius.CRITICAL,
        confidence: 1.0,
        failClosedTriggered: true
      };
    }

    // 2. Look for any explicit DENY across evaluators
    const denials = evaluations.filter(e => e.decision === Decision.DENY);
    if (denials.length > 0) {
      // Prioritize critical threat (indirect injection / exfiltration) if detected
      const highPriorityThreat = denials.find(d => d.riskFactor === 'INDIRECT_PROMPT_INJECTION') || denials[0];
      return {
        ...highPriorityThreat,
        allViolations: denials.map(d => ({ ruleId: d.ruleId, reason: d.reason })),
        failClosedTriggered: false
      };
    }

    // 3. Check for confidence threshold failure (< 0.85)
    for (const ev of evaluations) {
      if (ev.confidence !== undefined && ev.confidence < CONFIG.CONFIDENCE_THRESHOLD) {
        return {
          decision: Decision.DENY,
          reason: `Fail-Closed Security Override: Security confidence score (${ev.confidence}) is below threshold (${CONFIG.CONFIDENCE_THRESHOLD}). Action denied due to ambiguity.`,
          ruleId: 'RULE-FAIL-CLOSED-LOW-CONFIDENCE',
          blastRadius: BlastRadius.HIGH,
          confidence: ev.confidence,
          failClosedTriggered: true
        };
      }
    }

    // 4. Look for REQUIRE_APPROVAL
    const approvalRequired = evaluations.find(e => e.decision === Decision.REQUIRE_APPROVAL);
    if (approvalRequired) {
      return {
        ...approvalRequired,
        failClosedTriggered: false
      };
    }

    // 5. Default ALLOW (Only when all evaluators unanimously agreed ALLOW with high confidence)
    return {
      decision: Decision.ALLOW,
      reason: 'All defensive security checks passed with high confidence.',
      ruleId: 'RULE-PEP-PERMITTED',
      blastRadius: BlastRadius.LOW,
      confidence: 0.95,
      failClosedTriggered: false
    };
  }
}
