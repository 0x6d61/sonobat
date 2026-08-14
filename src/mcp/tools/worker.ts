import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { ActionRepository } from '../../db/repository/action-repository.js';
import { ArtifactRepository } from '../../db/repository/artifact-repository.js';
import { EngagementRepository } from '../../db/repository/engagement-repository.js';

export function registerWorkerTool(server: McpServer, db: Database.Database): void {
  const actions = new ActionRepository(db);
  const artifacts = new ArtifactRepository(db);
  const engagements = new EngagementRepository(db);
  server.tool(
    'worker',
    'Lease and finish Actions, register Artifact paths, and propose child Actions',
    {
      action: z.enum([
        'poll_action',
        'renew_action',
        'finish_action',
        'register_artifact',
        'propose_child_action',
      ]),
      id: z.string().optional(),
      workerId: z.string().optional(),
      kinds: z.array(z.string()).optional(),
      leaseSeconds: z.number().int().positive().optional(),
      state: z.enum(['completed', 'failed']).optional(),
      error: z.string().optional(),
      path: z.string().optional(),
      kind: z.string().optional(),
      dedupeKey: z.string().optional(),
      params: z.record(z.string(), z.unknown()).optional(),
      priority: z.number().int().optional(),
    },
    async (input) => {
      try {
        const workerId = required(input.workerId, 'workerId');
        if (input.action === 'poll_action') {
          const leased = actions.poll(workerId, input.kinds ?? [], input.leaseSeconds);
          return text(
            leased === undefined
              ? undefined
              : { action: leased, engagement: engagements.findById(leased.engagementId) },
          );
        }
        const id = required(input.id, 'id');
        const leased = actions.findById(id);
        if (!leased || leased.leaseOwner !== workerId || leased.state !== 'running') {
          throw new Error('Action lease is not owned by this worker');
        }
        if (input.action === 'renew_action') {
          return text(actions.renew(id, workerId, input.leaseSeconds));
        }
        if (input.action === 'finish_action') {
          if (!input.state) throw new Error('state is required');
          return text(actions.finish(id, workerId, input.state, input.error));
        }
        if (input.action === 'register_artifact') {
          return text(artifacts.create({ actionId: id, path: required(input.path, 'path') }));
        }
        return text(
          actions.create({
            engagementId: leased.engagementId,
            missionId: leased.missionId,
            parentActionId: id,
            kind: required(input.kind, 'kind'),
            dedupeKey: required(input.dedupeKey, 'dedupeKey'),
            params: input.params,
            priority: input.priority,
            state: 'proposed',
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
