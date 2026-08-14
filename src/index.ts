/**
 * sonobat — AttackDataGraph for autonomous penetration testing
 *
 * MCP Server エントリポイント。
 * stdio トランスポートで LLM Agent と接続する。
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { migrateDatabase } from './db/migrate.js';
import { createMcpServer } from './mcp/server.js';
import type { McpProfile } from './types/domain.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(resolve(__dirname, '../package.json'), 'utf-8')) as {
  version: string;
};

const DB_PATH = process.env['SONOBAT_DB_PATH'] ?? 'sonobat.db';
const PROFILE = process.env['SONOBAT_PROFILE'];
if (PROFILE !== 'tactical' && PROFILE !== 'worker') {
  throw new Error('SONOBAT_PROFILE must be tactical or worker');
}
const db = new Database(DB_PATH);
migrateDatabase(db);

const server = createMcpServer(db, pkg.version, PROFILE satisfies McpProfile);
const transport = new StdioServerTransport();
await server.connect(transport);
