import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import type { McpProfile } from '../types/domain.js';
import { registerQueryTool } from './tools/query.js';
import { registerMutateTool } from './tools/mutate.js';
import { registerKbTools } from './tools/kb.js';
import { registerMissionTool } from './tools/missions.js';
import { registerWorkerTool } from './tools/worker.js';
import { registerActionTool } from './tools/actions.js';
import { registerEvaluationTool } from './tools/evaluations.js';
import { registerEngagementTool } from './tools/engagements.js';

export function createMcpServer(
  db: Database.Database,
  version: string | undefined,
  profile: McpProfile,
): McpServer {
  const server = new McpServer({ name: `sonobat-${profile}`, version: version ?? '0.0.0' });

  registerQueryTool(server, db);
  registerMutateTool(server, db);
  registerEvaluationTool(server, db);

  if (profile === 'tactical') {
    registerEngagementTool(server, db);
    registerMissionTool(server, db);
    registerActionTool(server, db);
    registerKbTools(server, db);
  } else {
    registerWorkerTool(server, db);
  }

  return server;
}
