/**
 * sonobat — AttackDataGraph for autonomous penetration testing
 *
 * MCP Server エントリポイント。
 * stdio トランスポートで LLM Agent と接続する。
 */

import Database from 'better-sqlite3';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { migrateDatabase } from './db/migrate.js';
import { createMcpServer } from './mcp/server.js';

const DB_PATH = process.env['SONOBAT_DB_PATH'] ?? 'sonobat.db';
const db = new Database(DB_PATH);
migrateDatabase(db);

const server = createMcpServer(db);
const transport = new StdioServerTransport();
await server.connect(transport);
