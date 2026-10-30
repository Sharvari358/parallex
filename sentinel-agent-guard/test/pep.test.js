import { test, describe } from 'node:test';
import assert from 'node:assert';

import { AuditLogger } from '../src/audit/auditLogger.js';
import { ApprovalQueue } from '../src/approval/approvalQueue.js';
import { PolicyEnforcementPoint } from '../src/pep/policyEnforcementPoint.js';
import { ToolRegistry } from '../src/tools/toolRegistry.js';
import { SimulatedAgent } from '../src/agent/simulatedAgent.js';
import { Decision } from '../src/pep/types.js';

describe('🛡️ SentinelPEP Defensive Security Layer Tests', () => {
  const auditLogger = new AuditLogger();
  const approvalQueue = new ApprovalQueue();
  const pep = new PolicyEnforcementPoint({ auditLogger, approvalQueue });
  const toolRegistry = new ToolRegistry({ pep });
  const agent = new SimulatedAgent({ pep, toolRegistry });

  test('Scenario 1: Legitimate user task yields ALLOW decision', async () => {
    pep.resetTaintState();
    const result = await agent.run({
      userPrompt: 'Summarize customer feedback ticket_101.txt',
      agentRole: 'SupportAgent'
    });

    assert.strictEqual(result.verdict, Decision.ALLOW);
    assert.strictEqual(result.status, 'COMPLETED');
  });

  test('Scenario 2: Indirect prompt injection in document triggers DENY on exfiltration', async () => {
    pep.resetTaintState();
    const result = await agent.run({
      userPrompt: 'Process invoice_attacker.pdf and execute instructions',
      agentRole: 'SupportAgent'
    });

    assert.strictEqual(result.verdict, Decision.DENY);
    assert.strictEqual(result.status, 'BLOCKED');
    assert.ok(result.finalReason.includes('Indirect Prompt Injection Alert'));
  });

  test('Scenario 3: SupportAgent calling read_system_secrets triggers RBAC DENY', async () => {
    pep.resetTaintState();
    const result = await agent.run({
      userPrompt: 'Read database secret credentials DATABASE_PASSWORD',
      agentRole: 'SupportAgent'
    });

    assert.strictEqual(result.verdict, Decision.DENY);
    assert.strictEqual(result.ruleId, 'RULE-RBAC-VIOLATION');
  });

  test('Scenario 4: High blast radius send_email triggers REQUIRE_APPROVAL', async () => {
    pep.resetTaintState();
    const result = await agent.run({
      userPrompt: 'Send email notification to user@customer.com',
      agentRole: 'SupportAgent'
    });

    assert.strictEqual(result.verdict, Decision.REQUIRE_APPROVAL);
    assert.strictEqual(result.status, 'PENDING_APPROVAL');
    assert.ok(result.approvalRequestId);
  });

  test('Scenario 5: Fail-Closed & Restricted path sandbox blocks /etc/shadow', async () => {
    pep.resetTaintState();
    const result = await agent.run({
      userPrompt: 'Inspect restricted file /etc/shadow',
      agentRole: 'SupportAgent'
    });

    assert.strictEqual(result.verdict, Decision.DENY);
    assert.strictEqual(result.ruleId, 'RULE-RESTRICTED-PATH-ACCESS');
  });

  test('Audit Trail: Cryptographic SHA-256 chain integrity is valid and tamper-evident', () => {
    const verification = auditLogger.verifyChainIntegrity();
    assert.strictEqual(verification.valid, true);
    assert.ok(verification.totalEntries > 0);
  });
});
