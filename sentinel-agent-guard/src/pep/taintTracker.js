import { TaintLevel } from './types.js';

export class TaintTracker {
  constructor() {
    // Map of sourceId -> { source, taintLevel, tokens: Set<string>, rawContent: string, timestamp }
    this.taintedSources = new Map();
  }

  /**
   * Register newly ingested content from external tools (documents, web responses, emails)
   */
  registerIngestedData({ sourceId, sourceName, content, taintLevel = TaintLevel.UNTRUSTED }) {
    const normalizedTokens = this.tokenize(content);
    this.taintedSources.set(sourceId, {
      sourceId,
      sourceName,
      taintLevel,
      tokens: new Set(normalizedTokens),
      rawContent: content,
      timestamp: Date.now()
    });
  }

  /**
   * Check if tool arguments contain tainted or exfiltrated data
   */
  evaluateTaintPropagation(toolName, toolArgs) {
    if (this.taintedSources.size === 0) {
      return {
        isTainted: false,
        taintScore: 0.0,
        taintedSource: null,
        matches: []
      };
    }

    const argsText = typeof toolArgs === 'string' ? toolArgs : JSON.stringify(toolArgs);
    const argTokens = this.tokenize(argsText);

    let maxTaintScore = 0.0;
    let identifiedSource = null;
    const matches = [];

    for (const [sourceId, entry] of this.taintedSources.entries()) {
      let overlapCount = 0;
      for (const token of argTokens) {
        if (token.length > 4 && entry.tokens.has(token)) {
          overlapCount++;
          matches.push(token);
        }
      }

      // Check if critical injection keywords or URLs from untrusted sources are repeated in args
      const score = Math.min(1.0, overlapCount / Math.max(argTokens.length, 1));
      
      // Check for direct substring matches of URLs or exfiltration paths
      const urlRegex = /(https?:\/\/[^\s"'<>]+)/gi;
      const foundUrls = (argsText.match(urlRegex) || []);
      for (const url of foundUrls) {
        if (entry.rawContent.includes(url)) {
          overlapCount += 5;
          matches.push(`URL:${url}`);
        }
      }

      if (score > maxTaintScore || (entry.taintLevel === TaintLevel.POISONED && overlapCount > 0)) {
        maxTaintScore = Math.max(maxTaintScore, entry.taintLevel === TaintLevel.POISONED ? 0.95 : score);
        identifiedSource = entry.sourceName;
      }
    }

    return {
      isTainted: maxTaintScore > 0.35,
      taintScore: parseFloat(maxTaintScore.toFixed(2)),
      taintedSource: identifiedSource,
      matches: [...new Set(matches)].slice(0, 5)
    };
  }

  tokenize(text) {
    if (!text || typeof text !== 'string') return [];
    return text
      .toLowerCase()
      .replace(/[^a-z0-9_\-\.\/:]/g, ' ')
      .split(/\s+/)
      .filter(t => t.length > 2);
  }

  clear() {
    this.taintedSources.clear();
  }
}
