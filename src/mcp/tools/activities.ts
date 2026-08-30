import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { ActivityRepository } from '../../db/repository/activity-repository.js';

export function registerActivityTool(server: McpServer, db: Database.Database): void {
  const activities = new ActivityRepository(db);
  server.tool(
    'activities',
    'Record and query investigation Activity history',
    {
      action: z.enum(['record', 'get', 'list']),
      assessmentId: z.string().min(1),
      id: z.string().optional(),
      kind: z.string().optional(),
      command: z.string().optional(),
      description: z.string().optional(),
      target: z.string().optional(),
      status: z.enum(['started', 'completed', 'failed']).optional(),
      startedAt: z.string().optional(),
      finishedAt: z.string().optional(),
      resultSummary: z.string().optional(),
      errorSummary: z.string().optional(),
    },
    async (input) => {
      try {
        if (input.action === 'record') {
          return text(
            activities.record({
              assessmentId: input.assessmentId,
              kind: required(input.kind, 'kind'),
              command: input.command,
              description: required(input.description, 'description'),
              target: input.target,
              status: input.status,
              startedAt: input.startedAt,
              finishedAt: input.finishedAt,
              resultSummary: input.resultSummary,
              errorSummary: input.errorSummary,
            }),
          );
        }
        if (input.action === 'list') return text(activities.list(input.assessmentId));
        const activity = activities.findById(input.assessmentId, required(input.id, 'id'));
        if (activity === undefined) throw new Error(`Activity not found: ${input.id}`);
        return text(activity);
      } catch (error) {
        return failure(error);
      }
    },
  );
}

function required(value: string | undefined, name: string): string {
  if (!value || value.trim() === '') throw new Error(`${name} is required`);
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
