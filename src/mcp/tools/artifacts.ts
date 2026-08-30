import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { ArtifactRepository } from '../../db/repository/artifact-repository.js';

export function registerArtifactTool(server: McpServer, db: Database.Database): void {
  const artifacts = new ArtifactRepository(db);
  server.tool(
    'artifacts',
    'Register and query raw investigation evidence references',
    {
      action: z.enum(['register', 'get', 'list']),
      assessmentId: z.string().min(1),
      id: z.string().optional(),
      activityId: z.string().optional(),
      path: z.string().optional(),
      mediaType: z.string().optional(),
      sha256: z.string().optional(),
      capturedAt: z.string().optional(),
    },
    async (input) => {
      try {
        if (input.action === 'register') {
          return text(
            artifacts.create({
              assessmentId: input.assessmentId,
              activityId: input.activityId,
              path: required(input.path, 'path'),
              mediaType: input.mediaType,
              sha256: input.sha256,
              capturedAt: input.capturedAt,
            }),
          );
        }
        if (input.action === 'list')
          return text(artifacts.list(input.assessmentId, input.activityId));
        const artifact = artifacts.findById(input.id ?? '', input.assessmentId);
        if (artifact === undefined) throw new Error(`Artifact not found: ${input.id}`);
        return text(artifact);
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
