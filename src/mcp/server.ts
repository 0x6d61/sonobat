/**
 * sonobat — MCP Server
 *
 * Creates and configures the MCP server with all tools and resources.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { registerQueryTool } from './tools/query.js';
import { registerMutateTool } from './tools/mutate.js';
import { registerProposeTool } from './tools/propose.js';
import { registerKbTools } from './tools/kb.js';
import { registerOpsTools } from './tools/ops.js';
import { registerFindingsTools } from './tools/findings.js';
import { registerResources } from './resources.js';
import { registerMissionTool } from './tools/missions.js';
import { registerObservationTool } from './tools/observations.js';

/**
 * Create a fully configured MCP server with all sonobat tools and resources.
 *
 * @param db - The better-sqlite3 database instance
 * @param version - Package version string (read from package.json by caller)
 * @returns Configured McpServer instance
 */
export function createMcpServer(db: Database.Database, version?: string): McpServer {
  const server = new McpServer({
    name: 'sonobat',
    version: version ?? '0.0.0',
  });

  // Register tools
  registerQueryTool(server, db);
  registerMutateTool(server, db);
  registerProposeTool(server, db);
  registerKbTools(server, db); // search_kb + index_kb
  registerOpsTools(server, db); // ops (engagement/run/action management)
  registerFindingsTools(server, db); // findings (finding/risk management)
  registerMissionTool(server, db);
  registerObservationTool(server, db);

  // Register resources
  registerResources(server, db);

  return server;
}
