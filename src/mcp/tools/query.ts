import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { EntityRepository, RelationRepository } from '../../db/repository/entity-repository.js';

export function registerQueryTool(server: McpServer, db: Database.Database): void {
  const entities = new EntityRepository(db);
  const relations = new RelationRepository(db);
  server.tool(
    'query',
    'Query entities and relations in the Attack Data Graph',
    {
      action: z.enum(['list_entities', 'get_entity', 'list_relations', 'summary']),
      id: z.string().optional(),
      kind: z.string().optional(),
      entityId: z.string().optional(),
    },
    async (input) => {
      try {
        if (input.action === 'list_entities') return text(entities.list(input.kind));
        if (input.action === 'get_entity') {
          if (!input.id) throw new Error('id is required');
          const entity = entities.findById(input.id);
          if (!entity) throw new Error(`Entity not found: ${input.id}`);
          return text({ entity, relations: relations.list(entity.id) });
        }
        if (input.action === 'list_relations') return text(relations.list(input.entityId));
        const entityCount = (
          db.prepare('SELECT COUNT(*) count FROM entities').get() as {
            count: number;
          }
        ).count;
        const relationCount = (
          db.prepare('SELECT COUNT(*) count FROM relations').get() as {
            count: number;
          }
        ).count;
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
