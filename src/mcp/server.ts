/**
 * sonobat — MCP Server
 *
 * Creates and configures the MCP server with all tools and resources.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { registerQueryTools } from './tools/query.js';
import { registerIngestTool } from './tools/ingest.js';
import { registerProposeTool } from './tools/propose.js';
import { registerMutationTools } from './tools/mutation.js';
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
    version: '0.1.1',
  });

  // Register tools
  registerQueryTools(server, db);
  registerIngestTool(server, db);
  registerProposeTool(server, db);
  registerMutationTools(server, db);

  // Register resources
  registerResources(server, db);

  return server;
}
