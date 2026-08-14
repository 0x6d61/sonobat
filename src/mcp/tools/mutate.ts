import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { EntityRepository, RelationRepository } from '../../db/repository/entity-repository.js';

export function registerMutateTool(server: McpServer, db: Database.Database): void {
  const entities = new EntityRepository(db);
  const relations = new RelationRepository(db);
  server.tool(
    'mutate',
    'Register an Entity or Relation. Credential values are returned without masking.',
    {
      action: z.enum(['upsert_entity', 'upsert_relation']),
      kind: z.string().min(1),
      naturalKey: z.string().optional(),
      sourceEntityId: z.string().optional(),
      targetEntityId: z.string().optional(),
      properties: z.record(z.string(), z.unknown()).optional(),
      artifactId: z.string().optional(),
    },
    async (input) => {
      try {
        const result =
          input.action === 'upsert_entity'
            ? entities.upsert({
                kind: input.kind,
                naturalKey: required(input.naturalKey, 'naturalKey'),
                properties: input.properties,
                artifactId: input.artifactId,
              })
            : relations.upsert({
                kind: input.kind,
                sourceEntityId: required(input.sourceEntityId, 'sourceEntityId'),
                targetEntityId: required(input.targetEntityId, 'targetEntityId'),
                properties: input.properties,
                artifactId: input.artifactId,
              });
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
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
  if (value === undefined || value.trim() === '') throw new Error(`${name} is required`);
  return value;
}
