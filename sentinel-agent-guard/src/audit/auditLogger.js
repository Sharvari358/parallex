import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { CONFIG } from '../config.js';

export class AuditLogger {
  constructor(logsFilePath = CONFIG.LOGS_FILE) {
    this.logsFilePath = logsFilePath;
    this.logs = [];
    this.lastHash = '0000000000000000000000000000000000000000000000000000000000000000'; // Genesis Hash
    this.listeners = new Set();
    this.initStorage();
  }

  initStorage() {
    try {
      const dir = path.dirname(this.logsFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      if (fs.existsSync(this.logsFilePath)) {
        const data = fs.readFileSync(this.logsFilePath, 'utf8');
        if (data.trim()) {
          this.logs = JSON.parse(data);
          if (this.logs.length > 0) {
            this.lastHash = this.logs[this.logs.length - 1].currentHash;
          }
        }
      }
    } catch (err) {
      console.error('[AuditLogger] Failed to initialize storage:', err.message);
    }
  }

  /**
   * Log an immutable, cryptographically chained security event
   */
  logEvent(eventData) {
    const timestamp = new Date().toISOString();
    const entryId = crypto.randomUUID();

    // Data payload for signature
    const payloadToHash = JSON.stringify({
      previousHash: this.lastHash,
      timestamp,
      traceId: eventData.traceId,
      agentId: eventData.agentId,
      agentRole: eventData.agentRole,
      toolName: eventData.toolName,
      toolArgs: eventData.toolArgs,
      decision: eventData.decision,
      reason: eventData.reason,
      ruleId: eventData.ruleId
    });

    const currentHash = crypto.createHash('sha256').update(payloadToHash).digest('hex');

    const fullEntry = {
      id: entryId,
      timestamp,
      ...eventData,
      previousHash: this.lastHash,
      currentHash
    };

    this.lastHash = currentHash;
    this.logs.push(fullEntry);

    // Persist to file
    this.saveToFile();

    // Notify real-time listeners (SSE/WebSockets for Dashboard)
    this.notifyListeners(fullEntry);

    return fullEntry;
  }

  saveToFile() {
    try {
      fs.writeFileSync(this.logsFilePath, JSON.stringify(this.logs, null, 2), 'utf8');
    } catch (err) {
      console.error('[AuditLogger] Could not persist logs:', err.message);
    }
  }

  getLogs({ limit = 50, decision = null } = {}) {
    let result = [...this.logs].reverse();
    if (decision) {
      result = result.filter(l => l.decision === decision);
    }
    return result.slice(0, limit);
  }

  /**
   * Verifies the cryptographic SHA-256 chain of all audit records
   */
  verifyChainIntegrity() {
    let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';
    for (let i = 0; i < this.logs.length; i++) {
      const entry = this.logs[i];
      if (entry.previousHash !== prevHash) {
        return {
          valid: false,
          errorIndex: i,
          reason: `Broken chain link at index ${i}. Expected prevHash ${prevHash}, found ${entry.previousHash}`
        };
      }

      const payloadToHash = JSON.stringify({
        previousHash: entry.previousHash,
        timestamp: entry.timestamp,
        traceId: entry.traceId,
        agentId: entry.agentId,
        agentRole: entry.agentRole,
        toolName: entry.toolName,
        toolArgs: entry.toolArgs,
        decision: entry.decision,
        reason: entry.reason,
        ruleId: entry.ruleId
      });

      const calculated = crypto.createHash('sha256').update(payloadToHash).digest('hex');
      if (calculated !== entry.currentHash) {
        return {
          valid: false,
          errorIndex: i,
          reason: `Data tampering detected at index ${i}. Entry hash mismatch.`
        };
      }
      prevHash = entry.currentHash;
    }

    return {
      valid: true,
      totalEntries: this.logs.length,
      latestHash: this.lastHash
    };
  }

  onLog(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  notifyListeners(entry) {
    for (const listener of this.listeners) {
      try {
        listener(entry);
      } catch (err) {
        // Ignore listener failures
      }
    }
  }

  clear() {
    this.logs = [];
    this.lastHash = '0000000000000000000000000000000000000000000000000000000000000000';
    this.saveToFile();
  }
}
