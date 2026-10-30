import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';

describe('🌐 SentinelPEP Server & API Integration Tests', () => {
  let serverProcess;
  const baseUrl = 'http://127.0.0.1:4000';

  // Helper for HTTP requests
  function makeRequest(method, path, body = null) {
    return new Promise((resolve, reject) => {
      const url = new URL(path, baseUrl);
      const req = http.request(url, {
        method,
        headers: { 'Content-Type': 'application/json' }
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk.toString(); });
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(data) });
          } catch (e) {
            resolve({ status: res.statusCode, text: data });
          }
        });
      });
      req.on('error', reject);
      if (body) req.write(JSON.stringify(body));
      req.end();
    });
  }

  // We can import server directly or launch it
  let serverInstance;

  before(async () => {
    // Import and start server dynamically
    process.env.PORT = '4005';
    // Let's test against port 4005
  });

  test('Module exports and initialization work cleanly', async () => {
    const { AuditLogger } = await import('../src/audit/auditLogger.js');
    const logger = new AuditLogger();
    assert.ok(logger);
  });
});
