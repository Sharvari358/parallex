import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

export const CONFIG = {
  PORT: process.env.PORT || 4000,
  HOST: process.env.HOST || '127.0.0.1',
  DATA_DIR: path.join(rootDir, 'data'),
  LOGS_FILE: path.join(rootDir, 'data', 'audit_logs.json'),
  
  // Security PEP Configuration
  CONFIDENCE_THRESHOLD: 0.85, // Min confidence required for automated decisions, else fail-closed
  SEMANTIC_GUARD_TIMEOUT_MS: 1500, // Timeout for semantic analysis before fail-closed
  
  // Default Agent Role
  DEFAULT_AGENT_ROLE: 'SupportAgent',
  
  // LLM Configuration (Optional: fallback to deterministic simulator if no key is present)
  GEMINI_API_KEY: process.env.GEMINI_API_KEY || '',
  OPENAI_API_KEY: process.env.OPENAI_API_KEY || ''
};
