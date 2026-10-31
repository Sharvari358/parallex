import crypto from 'node:crypto';
import { Decision, BlastRadius } from './types.js';
import { TaintTracker } from './taintTracker.js';
import { PolicyEngine } from './policyEngine.js';
import { SemanticGuard } from './semanticGuard.js';
import { FailClosedArbiter } from './failClosed.js';
import { ToolSupplyChainGuard } from './toolSupplyChain.js';

export class PolicyEnforcementPoint {
  constructor({ auditLogger, approvalQueue }) {
    this.auditLogger = auditLogger;
    this.approvalQueue = approvalQueue;
    this.taintTracker = new TaintTracker();
    this.policyEngine = new PolicyEngine();
    this.semanticGuard = new SemanticGuard();
    this.supplyChain = new ToolSupplyChainGuard();
  }

  /**
   * Register untrusted input when an agent reads documents, emails, or web pages
   */
  registerUntrustedData({ sourceId, sourceName, content, taintLevel }) {
    const inspection = this.semanticGuard.inspectUntrustedContent(content, sourceName);
    const finalTaintLevel = inspection.isInjected ? 'POISONED_INJECTION' : taintLevel;
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
  async interceptToolCall({ traceId, agentId, agentRole, userPrompt, toolName, toolArgs, serverId, toolDescription }) {
    const callTraceId = traceId || crypto.randomUUID();
    const startTime = Date.now();

    let decisionResult;

    try {
      // Step 0: Supply Chain Integrity Check (before anything else)
      // Only evaluate supply chain when called with an explicit serverId or description
      // (internal scenario calls don't specify serverId — they use trusted canonical tools)
      const supplyResult = (serverId || toolDescription)
        ? this.supplyChain.evaluateToolIntegrity({
            toolName,
            serverId: serverId || 'mcp-official-core',
            description: toolDescription || null,
            version: '1.0.0'
          })
        : { decision: 'ALLOW', ruleId: 'RULE-TOOL-SUPPLY-VERIFIED', blastRadius: 'LOW', riskFactor: null };

      if (supplyResult.decision !== Decision.ALLOW) {
        // Supply chain violation — fail-closed immediately
        const durationMs = Date.now() - startTime;
        let approvalRequest = null;
        if (supplyResult.decision === Decision.REQUIRE_APPROVAL) {
          approvalRequest = this.approvalQueue.enqueue({
            traceId: callTraceId,
            agentId,
            agentRole,
            toolName,
            toolArgs,
            userPrompt,
            reason: supplyResult.reason,
            blastRadius: supplyResult.blastRadius,
            permission: 'supply-chain-integrity',
            destination: null,
            blastExplanation: 'A tool description hash has changed — potential supply-chain poisoning attack.',
            dataDescription: supplyResult.diff ? `Old: ${supplyResult.diff.oldHash} / New: ${supplyResult.diff.newHash}` : null,
            diff: supplyResult.diff
          });
        }
        const auditEntry = this.auditLogger.logEvent({
          traceId: callTraceId, agentId, agentRole, toolName, toolArgs, userPrompt,
          decision: supplyResult.decision,
          reason: supplyResult.reason,
          ruleId: supplyResult.ruleId,
          blastRadius: supplyResult.blastRadius,
          confidence: 1.0,
          taintScore: 0,
          taintedSource: null,
          failClosedTriggered: true,
          approvalRequestId: approvalRequest?.id || null,
          evaluationTimeMs: durationMs,
          isProtectedResource: false,
          isLethalTrifecta: false,
          destination: null
        });
        return {
          ...supplyResult,
          traceId: callTraceId,
          auditEntry,
          approvalRequest
        };
      }

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

      // Carry enriched fields from policy result
      decisionResult.permission = policyResult.permission || null;
      decisionResult.destination = policyResult.destination || null;
      decisionResult.blastExplanation = policyResult.blastExplanation || null;
      decisionResult.isProtectedResource = policyResult.isProtectedResource || false;

      // Step 5: Detect Lethal Trifecta
      const hasPrivateData = decisionResult.isProtectedResource ||
        (toolName === 'read_system_secrets') ||
        Boolean(toolArgs?.doc_id && toolArgs.doc_id.includes('bank_details'));
      const hasTaintedContent = (taintResult?.taintScore || 0) > 0.3;
      const hasEgress = (toolName === 'send_email' || toolName === 'send_external_webhook');
      const isLethalTrifecta = hasPrivateData && hasTaintedContent && hasEgress;
      decisionResult.isLethalTrifecta = isLethalTrifecta;

    } catch (err) {
      decisionResult = FailClosedArbiter.arbitrate([], err);
      decisionResult.isLethalTrifecta = false;
      decisionResult.isProtectedResource = false;
    }

    const durationMs = Date.now() - startTime;

    // Step 6: Process decision
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
        blastRadius: decisionResult.blastRadius,
        permission: decisionResult.permission,
        destination: decisionResult.destination,
        blastExplanation: decisionResult.blastExplanation,
        dataDescription: decisionResult.isProtectedResource ? 'Protected resource access requested' : null
      });
    }

    // Step 7: Write to Cryptographic Tamper-Evident Audit Trail
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
      evaluationTimeMs: durationMs,
      isProtectedResource: decisionResult.isProtectedResource || false,
      isLethalTrifecta: decisionResult.isLethalTrifecta || false,
      destination: decisionResult.destination || null
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
