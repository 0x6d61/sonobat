import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { AssessmentRepository } from '../../db/repository/assessment-repository.js';
import { ActivityRepository } from '../../db/repository/activity-repository.js';
import { ArtifactRepository } from '../../db/repository/artifact-repository.js';
import { EntityRepository, RelationRepository } from '../../db/repository/entity-repository.js';

export function registerAssessmentTool(server: McpServer, db: Database.Database): void {
  const assessments = new AssessmentRepository(db);
  const activities = new ActivityRepository(db);
  const artifacts = new ArtifactRepository(db);
  const entities = new EntityRepository(db);
  const relations = new RelationRepository(db);
  server.tool(
    'assessments',
    'Create and query Assessment namespaces',
    {
      action: z.enum(['create', 'get', 'list', 'get_context']),
      id: z.string().optional(),
      assessmentId: z.string().optional(),
      name: z.string().optional(),
    },
    async (input) => {
      try {
        if (input.action === 'get_context') {
          const assessmentId = required(input.assessmentId ?? input.id, 'assessmentId');
          const assessment = assessments.findById(assessmentId);
          if (assessment === undefined) throw new Error(`Assessment not found: ${assessmentId}`);
          return text({
            assessment,
            entities: entities.list(assessmentId),
            relations: relations.list(undefined, assessmentId),
            activities: activities.list(assessmentId),
            artifacts: artifacts.list(assessmentId),
          });
        }
        const value =
          input.action === 'create'
            ? assessments.create({ name: required(input.name, 'name') })
            : input.action === 'get'
              ? assessments.findById(required(input.id, 'id'))
              : assessments.list();
        if (input.action === 'get' && value === undefined) {
          throw new Error(`Assessment not found: ${input.id}`);
        }
        return text(value);
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
