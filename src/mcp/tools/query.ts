import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { EntityRepository, RelationRepository } from '../../db/repository/entity-repository.js';
import { ArtifactRepository } from '../../db/repository/artifact-repository.js';
import { resolveAssessmentId } from '../../db/repository/assessment-scope.js';

export function registerQueryTool(server: McpServer, db: Database.Database): void {
  const entities = new EntityRepository(db);
  const relations = new RelationRepository(db);
  const artifacts = new ArtifactRepository(db);
  server.tool(
    'query',
    'Query the Assessment Entity and Relation graph and its Artifact references',
    {
      action: z.enum([
        'list_entities',
        'get_entity',
        'list_relations',
        'list_artifacts',
        'summary',
      ]),
      assessmentId: z.string().optional(),
      id: z.string().optional(),
      kind: z.string().optional(),
      entityId: z.string().optional(),
    },
    async (input) => {
      try {
        if (input.action === 'list_entities') {
          return text(entities.list(input.assessmentId, input.kind));
        }
        if (input.action === 'get_entity') {
          if (!input.id) throw new Error('id is required');
          const assessmentId = resolveAssessmentId(db, input.assessmentId);
          const entity = entities.findById(input.id, assessmentId);
          if (!entity) throw new Error(`Entity not found: ${input.id}`);
          return text({ entity, relations: relations.list(entity.id, assessmentId) });
        }
        if (input.action === 'list_relations') {
          return text(relations.list(input.entityId, input.assessmentId));
        }
        if (input.action === 'list_artifacts') {
          return text(artifacts.list(input.assessmentId));
        }
        const assessmentId = resolveAssessmentId(db, input.assessmentId);
        const entityCount = entities.list(assessmentId).length;
        const relationCount = relations.list(undefined, assessmentId).length;
        return text({ entities: entityCount, relations: relationCount });
      } catch (error) {
        return failure(error);
      }
    },
  );
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
