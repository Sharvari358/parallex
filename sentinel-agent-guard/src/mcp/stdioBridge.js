#!/usr/bin/env node

/**
 * SentinelPEP Model Context Protocol (MCP) Stdio Gateway Bridge
 * 
 * Enables standard MCP clients (Claude Desktop, Cursor, LangChain)
 * to govern tool executions through the Sentinel Policy Enforcement Point.
 */

import readline from 'node:readline';
import { AuditLogger } from '../audit/auditLogger.js';
import { ApprovalQueue } from '../approval/approvalQueue.js';
import { PolicyEnforcementPoint } from '../pep/policyEnforcementPoint.js';
import { ToolRegistry } from '../tools/toolRegistry.js';
import { MCPGateway } from './mcpGateway.js';

const auditLogger = new AuditLogger();
const approvalQueue = new ApprovalQueue();
const pep = new PolicyEnforcementPoint({ auditLogger, approvalQueue });
const toolRegistry = new ToolRegistry({ pep });
const mcpGateway = new MCPGateway({ pep, toolRegistry });

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', async (line) => {
  if (!line.trim()) return;

  try {
    const request = JSON.parse(line);
    const response = await mcpGateway.handleRpcRequest(request);
    process.stdout.write(JSON.stringify(response) + '\n');
  } catch (err) {
    const errResponse = {
      jsonrpc: '2.0',
      id: null,
      error: {
        code: -32700,
        message: 'Parse error: ' + err.message
      }
    };
    process.stdout.write(JSON.stringify(errResponse) + '\n');
  }
});

process.on('SIGINT', () => process.exit(0));
