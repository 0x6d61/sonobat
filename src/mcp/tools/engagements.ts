import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { EngagementRepository } from '../../db/repository/engagement-repository.js';

export function registerEngagementTool(server: McpServer, db: Database.Database): void {
  const engagements = new EngagementRepository(db);
  server.tool(
    'engagements',
    'Create and inspect authorized assessment boundaries',
    {
      action: z.enum(['create', 'get', 'list']),
      id: z.string().optional(),
      name: z.string().optional(),
      environment: z.string().optional(),
      scopeJson: z.string().optional(),
      policyJson: z.string().optional(),
    },
    async (input) => {
      try {
        const value =
          input.action === 'create'
            ? engagements.create({
                name: required(input.name, 'name'),
                environment: input.environment,
                scopeJson: input.scopeJson,
                policyJson: input.policyJson,
              })
            : input.action === 'get'
              ? engagements.findById(required(input.id, 'id'))
              : engagements.list();
        return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
      } catch (error) {
        return {
          content: [{ type: 'text', text: error instanceof Error ? error.message : String(error) }],
          isError: true,
        };
      }
    },
  );
}

function required(value: string | undefined, name: string): string {
  if (!value) throw new Error(`${name} is required`);
  return value;
}
