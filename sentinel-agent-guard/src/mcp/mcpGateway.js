import { Decision } from '../pep/types.js';

export class MCPGateway {
  constructor({ pep, toolRegistry }) {
    this.pep = pep;
    this.toolRegistry = toolRegistry;
  }

  /**
   * Handle JSON-RPC 2.0 MCP Request
   */
  async handleRpcRequest(rpcRequest) {
    const { id, method, params } = rpcRequest || {};

    if (!method) {
      return this.formatRpcError(id, -32600, 'Invalid Request: missing method');
    }

    try {
      switch (method) {
        case 'tools/list':
          return this.handleListTools(id);

        case 'tools/call':
          return await this.handleCallTool(id, params);

        case 'ping':
          return { jsonrpc: '2.0', id, result: { status: 'healthy', version: '1.0.0-sentinel-mcp' } };

        default:
          return this.formatRpcError(id, -32601, `Method not found: '${method}'`);
      }
    } catch (err) {
      return this.formatRpcError(id, -32603, `Internal security gateway error: ${err.message}`);
    }
  }

  handleListTools(id) {
    const tools = this.toolRegistry.getToolDefinitions().map(tool => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.parameters,
      // Enhanced Sentinel MCP Security Metadata
      'x-sentinel-blast-radius': tool.blastRadius,
      'x-sentinel-pep-governed': true
    }));

    return {
      jsonrpc: '2.0',
      id,
      result: { tools }
    };
  }

  async handleCallTool(id, params) {
    const { name: toolName, arguments: toolArgs, _meta } = params || {};
    const agentRole = _meta?.agentRole || 'SupportAgent';
    const userPrompt = _meta?.userPrompt || 'External MCP tool call';
    const traceId = _meta?.traceId;

    // 1. Policy Enforcement Point Interception
    const interception = await this.pep.interceptToolCall({
      traceId,
      agentId: _meta?.agentId || 'mcp-client',
      agentRole,
      userPrompt,
      toolName,
      toolArgs
    });

    // 2. Denied by PEP
    if (interception.decision === Decision.DENY) {
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32001, // Custom MCP Security Violation code
          message: `Sentinel PEP Violation: ${interception.reason}`,
          data: {
            ruleId: interception.ruleId,
            blastRadius: interception.blastRadius,
            confidence: interception.confidence,
            failClosed: interception.failClosedTriggered
          }
        }
      };
    }

    // 3. Approval Required
    if (interception.decision === Decision.REQUIRE_APPROVAL) {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          isError: true,
          status: 'PENDING_APPROVAL',
          message: `Action paused. High blast radius action requires operator approval.`,
          approvalRequestId: interception.approvalRequest?.id
        }
      };
    }

    // 4. Allowed - Delegate to underlying tool
    const executionResult = await this.toolRegistry.executeTool(toolName, toolArgs);
    return {
      jsonrpc: '2.0',
      id,
      result: {
        content: [
          {
            type: 'text',
            text: JSON.stringify(executionResult)
          }
        ],
        _sentinelPEP: {
          status: 'ALLOWED',
          ruleId: interception.ruleId,
          confidence: interception.confidence
        }
      }
    };
  }

  formatRpcError(id, code, message) {
    return {
      jsonrpc: '2.0',
      id: id ?? null,
      error: { code, message }
    };
  }
}
