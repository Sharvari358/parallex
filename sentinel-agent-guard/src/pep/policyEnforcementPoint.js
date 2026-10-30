import crypto from 'node:crypto';
import { Decision } from './types.js';
import { TaintTracker } from './taintTracker.js';
import { PolicyEngine } from './policyEngine.js';
import { SemanticGuard } from './semanticGuard.js';
import { FailClosedArbiter } from './failClosed.js';

export class PolicyEnforcementPoint {
  constructor({ auditLogger, approvalQueue }) {
    this.auditLogger = auditLogger;
    this.approvalQueue = approvalQueue;
    this.taintTracker = new TaintTracker();
    this.policyEngine = new PolicyEngine();
    this.semanticGuard = new SemanticGuard();
  }

  /**
   * Register untrusted input when an agent reads documents, emails, or web pages
   */
  registerUntrustedData({ sourceId, sourceName, content, taintLevel }) {
    // 1. Inspect for indirect injections
    const inspection = this.semanticGuard.inspectUntrustedContent(content, sourceName);
    const finalTaintLevel = inspection.isInjected ? 'POISONED_INJECTION' : taintLevel;

    // 2. Register in Taint Tracker
    this.taintTracker.registerIngestedData({
      sourceId,
      sourceName,
      content,
      taintLevel: finalTaintLevel
    });

    return inspection;
  }

  /**
   * The core interceptor: sits directly in front of all tool invocations
   */
  async interceptToolCall({ traceId, agentId, agentRole, userPrompt, toolName, toolArgs }) {
    const callTraceId = traceId || crypto.randomUUID();
    const startTime = Date.now();

    let decisionResult;

    try {
      // Step 1: Taint & Provenance Analysis
      const taintResult = this.taintTracker.evaluateTaintPropagation(toolName, toolArgs);

      // Step 2: Policy & RBAC Evaluation
      const policyResult = this.policyEngine.evaluate({ agentRole, toolName, toolArgs });

      // Step 3: Semantic Guard & Intent Alignment
      const semanticResult = this.semanticGuard.evaluateIntentAlignment({
        userPrompt,
        toolName,
        toolArgs,
        taintResult
      });

      // Step 4: Fail-Closed Arbitration
      decisionResult = FailClosedArbiter.arbitrate([policyResult, semanticResult]);
      decisionResult.taintResult = taintResult;

    } catch (err) {
      // Fail-Closed on any unhandled evaluation exception
      decisionResult = FailClosedArbiter.arbitrate([], err);
    }

    const durationMs = Date.now() - startTime;

    // Step 5: Process decision
    let approvalRequest = null;
    if (decisionResult.decision === Decision.REQUIRE_APPROVAL) {
      approvalRequest = this.approvalQueue.enqueue({
        traceId: callTraceId,
        agentId,
        agentRole,
        toolName,
        toolArgs,
        userPrompt,
        reason: decisionResult.reason,
        blastRadius: decisionResult.blastRadius
      });
    }

    // Step 6: Write to Cryptographic Tamper-Evident Audit Trail
    const auditEntry = this.auditLogger.logEvent({
      traceId: callTraceId,
      agentId,
      agentRole,
      toolName,
      toolArgs,
      userPrompt,
      decision: decisionResult.decision,
      reason: decisionResult.reason,
      ruleId: decisionResult.ruleId,
      blastRadius: decisionResult.blastRadius,
      confidence: decisionResult.confidence,
      taintScore: decisionResult.taintResult?.taintScore || 0.0,
      taintedSource: decisionResult.taintResult?.taintedSource || null,
      failClosedTriggered: Boolean(decisionResult.failClosedTriggered),
      approvalRequestId: approvalRequest ? approvalRequest.id : null,
      evaluationTimeMs: durationMs
    });

    return {
      ...decisionResult,
      traceId: callTraceId,
      auditEntry,
      approvalRequest
    };
  }

  resetTaintState() {
    this.taintTracker.clear();
  }
}
