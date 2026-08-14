import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { ActionRepository } from '../../db/repository/action-repository.js';

export function registerActionTool(server: McpServer, db: Database.Database): void {
  const actions = new ActionRepository(db);
  server.tool(
    'actions',
    'Create, list, inspect, and adopt Actions',
    {
      action: z.enum(['create', 'get', 'list', 'adopt']),
      id: z.string().optional(),
      engagementId: z.string().optional(),
      missionId: z.string().optional(),
      kind: z.string().optional(),
      dedupeKey: z.string().optional(),
      params: z.record(z.string(), z.unknown()).optional(),
      priority: z.number().int().optional(),
      maxAttempts: z.number().int().positive().optional(),
    },
    async (input) => {
      try {
        if (input.action === 'create') {
          return text(
            actions.create({
              engagementId: required(input.engagementId, 'engagementId'),
              missionId: input.missionId,
              kind: required(input.kind, 'kind'),
              dedupeKey: required(input.dedupeKey, 'dedupeKey'),
              params: input.params,
              priority: input.priority,
              maxAttempts: input.maxAttempts,
            }),
          );
        }
        if (input.action === 'list') return text(actions.list(input.missionId));
        const id = required(input.id, 'id');
        return text(input.action === 'adopt' ? actions.adopt(id) : actions.findById(id));
      } catch (error) {
        return failure(error);
      }
    },
  );
}

function required(value: string | undefined, name: string): string {
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function text(value: unknown): { content: [{ type: 'text'; text: string }] } {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

function failure(error: unknown): {
  content: [{ type: 'text'; text: string }];
  isError: true;
} {
  return {
    content: [{ type: 'text', text: error instanceof Error ? error.message : String(error) }],
    isError: true,
  };
}
