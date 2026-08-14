import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { HypothesisRepository } from '../../db/repository/hypothesis-repository.js';

export function registerEvaluationTool(server: McpServer, db: Database.Database): void {
  const hypotheses = new HypothesisRepository(db);
  server.tool(
    'evaluations',
    'Create and evaluate attack hypotheses, including dismissed high-cost hypotheses',
    {
      action: z.enum(['create_hypothesis', 'get_hypothesis', 'list_hypotheses', 'evaluate']),
      id: z.string().optional(),
      engagementId: z.string().optional(),
      missionId: z.string().optional(),
      title: z.string().optional(),
      objective: z.string().optional(),
      status: z.enum(['active', 'validated', 'rejected', 'dismissed']).optional(),
      preconditions: z.array(z.unknown()).optional(),
      blockers: z.array(z.unknown()).optional(),
      validationResult: z.record(z.string(), z.unknown()).optional(),
      reason: z.string().optional(),
      artifactId: z.string().optional(),
    },
    async (input) => {
      try {
        if (input.action === 'create_hypothesis') {
          return text(
            hypotheses.create({
              engagementId: required(input.engagementId, 'engagementId'),
              missionId: input.missionId,
              title: required(input.title, 'title'),
              objective: required(input.objective, 'objective'),
              preconditions: input.preconditions,
              blockers: input.blockers,
              artifactId: input.artifactId,
            }),
          );
        }
        if (input.action === 'list_hypotheses') {
          return text(hypotheses.list(required(input.engagementId, 'engagementId')));
        }
        const id = required(input.id, 'id');
        if (input.action === 'get_hypothesis') return text(hypotheses.findById(id));
        if (!input.status) throw new Error('status is required');
        return text(
          hypotheses.evaluate({
            id,
            status: input.status,
            validationResult: input.validationResult,
            reason: input.reason,
            artifactId: input.artifactId,
          }),
        );
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
