/**
 * sonobat — MCP Propose Tool
 *
 * Tool for generating next-step action proposals based on missing data.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { propose } from '../../engine/proposer.js';

export function registerProposeTool(server: McpServer, db: Database.Database): void {
  server.tool(
    'propose',
    'Analyze the AttackDataGraph for missing data and propose next-step actions',
    {
      hostId: z.string().optional().describe('Limit proposals to a specific host (optional)'),
    },
    async ({ hostId }) => {
      const actions = propose(db, hostId);
      if (actions.length === 0) {
        return {
          content: [
            { type: 'text', text: 'No actions proposed. All discovered data appears complete.' },
          ],
        };
      }
      return { content: [{ type: 'text', text: JSON.stringify(actions, null, 2) }] };
    },
  );
}
