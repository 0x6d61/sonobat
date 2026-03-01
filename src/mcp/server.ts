/**
 * sonobat — MCP Server
 *
 * Creates and configures the MCP server with all tools and resources.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { registerQueryTool } from './tools/query.js';
import { registerMutateTool } from './tools/mutate.js';
import { registerIngestTool } from './tools/ingest.js';
import { registerProposeTool } from './tools/propose.js';
import { registerKbTools } from './tools/kb.js';
import { registerResources } from './resources.js';

/**
 * Create a fully configured MCP server with all sonobat tools and resources.
 *
 * @param db - The better-sqlite3 database instance
 * @returns Configured McpServer instance
 */
export function createMcpServer(db: Database.Database): McpServer {
  const server = new McpServer({
    name: 'sonobat',
    version: '0.4.0',
  });

  // Register tools (6 tools total)
  registerQueryTool(server, db);
  registerMutateTool(server, db);
  registerIngestTool(server, db);
  registerProposeTool(server, db);
  registerKbTools(server, db); // search_kb + index_kb

  // Register resources
  registerResources(server, db);

  return server;
}
