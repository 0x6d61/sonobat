import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { registerQueryTool } from './tools/query.js';
import { registerMutateTool } from './tools/mutate.js';
import { registerActivityTool } from './tools/activities.js';
import { registerAssessmentTool } from './tools/assessments.js';
import { registerArtifactTool } from './tools/artifacts.js';

export function createMcpServer(db: Database.Database, version?: string): McpServer {
  const server = new McpServer({ name: 'sonobat', version: version ?? '0.0.0' });
  registerAssessmentTool(server, db);
  registerQueryTool(server, db);
  registerMutateTool(server, db);
  registerActivityTool(server, db);
  registerArtifactTool(server, db);
  return server;
}
