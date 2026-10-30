import crypto from 'node:crypto';

export class ApprovalQueue {
  constructor() {
    this.pendingRequests = new Map();
    this.history = [];
    this.listeners = new Set();
  }

  enqueue({ traceId, agentId, agentRole, toolName, toolArgs, userPrompt, reason, blastRadius }) {
    const id = crypto.randomUUID();
    const request = {
      id,
      traceId,
      agentId,
      agentRole,
      toolName,
      toolArgs,
      userPrompt,
      reason,
      blastRadius,
      status: 'PENDING',
      createdAt: new Date().toISOString()
    };

    this.pendingRequests.set(id, request);
    this.notify({ type: 'ENQUEUED', request });
    return request;
  }

  approve(id, operatorNotes = 'Approved by security operator') {
    const req = this.pendingRequests.get(id);
    if (!req) {
      throw new Error(`Approval request '${id}' not found.`);
    }

    req.status = 'APPROVED';
    req.decidedAt = new Date().toISOString();
    req.operatorNotes = operatorNotes;

    this.pendingRequests.delete(id);
    this.history.push(req);
    this.notify({ type: 'APPROVED', request: req });
    return req;
  }

  reject(id, operatorReason = 'Rejected by security operator') {
    const req = this.pendingRequests.get(id);
    if (!req) {
      throw new Error(`Approval request '${id}' not found.`);
    }

    req.status = 'REJECTED';
    req.decidedAt = new Date().toISOString();
    req.operatorReason = operatorReason;

    this.pendingRequests.delete(id);
    this.history.push(req);
    this.notify({ type: 'REJECTED', request: req });
    return req;
  }

  getPending() {
    return Array.from(this.pendingRequests.values());
  }

  getHistory() {
    return [...this.history].reverse().slice(0, 50);
  }

  onUpdate(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  notify(event) {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch (err) {}
    }
  }

  clear() {
    this.pendingRequests.clear();
    this.history = [];
  }
}
