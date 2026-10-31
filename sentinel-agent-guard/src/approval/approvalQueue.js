import crypto from 'node:crypto';

export class ApprovalQueue {
  constructor() {
    this.pendingRequests = new Map();
    this.history = [];
    this.listeners = new Set();
    this.timeouts = new Map();
  }

  enqueue({
    traceId, agentId, agentRole, toolName, toolArgs, userPrompt,
    reason, blastRadius,
    permission = null,
    destination = null,
    blastExplanation = null,
    dataDescription = null,
    diff = null,
    timeoutMs = 30000
  }) {
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
      permission,
      destination,
      blastExplanation,
      dataDescription,
      diff,
      status: 'PENDING',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + timeoutMs).toISOString()
    };

    this.pendingRequests.set(id, request);
    this.notify({ type: 'ENQUEUED', request });

    // Fail-closed: auto-reject after timeoutMs
    const timer = setTimeout(() => {
      if (this.pendingRequests.has(id)) {
        const req = this.pendingRequests.get(id);
        req.status = 'REJECTED';
        req.decidedAt = new Date().toISOString();
        req.operatorNotes = 'no human authorization — 30-second timeout expired';
        req.timedOut = true;
        this.pendingRequests.delete(id);
        this.history.push(req);
        this.timeouts.delete(id);
        this.notify({ type: 'TIMEOUT_REJECTED', request: req });
      }
    }, timeoutMs);

    this.timeouts.set(id, timer);
    return request;
  }

  approve(id, operatorNotes = 'Approved by security operator') {
    const req = this.pendingRequests.get(id);
    if (!req) throw new Error(`Approval request '${id}' not found.`);

    // Cancel auto-timeout
    const timer = this.timeouts.get(id);
    if (timer) { clearTimeout(timer); this.timeouts.delete(id); }

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
    if (!req) throw new Error(`Approval request '${id}' not found.`);

    // Cancel auto-timeout
    const timer = this.timeouts.get(id);
    if (timer) { clearTimeout(timer); this.timeouts.delete(id); }

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
      try { listener(event); } catch (err) {}
    }
  }

  clear() {
    // Cancel all timeouts
    for (const timer of this.timeouts.values()) clearTimeout(timer);
    this.timeouts.clear();
    this.pendingRequests.clear();
    this.history = [];
  }
}
