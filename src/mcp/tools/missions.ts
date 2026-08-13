import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { MissionRepository } from '../../db/repository/mission-repository.js';
import { ActionQueueRepository } from '../../db/repository/action-queue-repository.js';
import { ActionContextRepository } from '../../db/repository/action-context-repository.js';

export function registerMissionTool(server: McpServer, db: Database.Database): void {
  const missions = new MissionRepository(db);
  const actions = new ActionQueueRepository(db);
  const contexts = new ActionContextRepository(db);
  server.tool(
    'missions',
    'Manage missions and retrieve action context',
    {
      action: z.enum(['create', 'get', 'list', 'complete', 'tree', 'context']),
      id: z.string().optional(),
      engagementId: z.string().optional(),
      runId: z.string().optional(),
      objective: z.string().optional(),
      targetsJson: z.string().optional(),
      successConditionsJson: z.string().optional(),
      stopConditionsJson: z.string().optional(),
      targetNodeIds: z.array(z.string()).optional(),
      edgeKinds: z.array(z.string()).optional(),
      depth: z.number().int().min(0).max(10).optional(),
    },
    async (input) => {
      try {
        if (input.action === 'create') {
          if (!input.engagementId || !input.objective)
            throw new Error('engagementId and objective are required');
          const mission = missions.create({
            engagementId: input.engagementId,
            runId: input.runId,
            objective: input.objective,
            targetsJson: input.targetsJson,
            successConditionsJson: input.successConditionsJson,
            stopConditionsJson: input.stopConditionsJson,
          });
          return { content: [{ type: 'text', text: JSON.stringify(mission, null, 2) }] };
        }
        if (input.action === 'list') {
          if (!input.engagementId) throw new Error('engagementId is required');
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(missions.findByEngagement(input.engagementId), null, 2),
              },
            ],
          };
        }
        if (!input.id) throw new Error('id is required');
        if (input.action === 'get') {
          const mission = missions.findById(input.id);
          if (!mission) throw new Error(`Mission not found: ${input.id}`);
          return { content: [{ type: 'text', text: JSON.stringify(mission, null, 2) }] };
        }
        if (input.action === 'complete') {
          const mission = missions.complete(input.id);
          if (!mission) throw new Error(`Mission not found: ${input.id}`);
          return { content: [{ type: 'text', text: JSON.stringify(mission, null, 2) }] };
        }
        if (input.action === 'tree') {
          const mission = missions.findById(input.id);
          if (!mission) throw new Error(`Mission not found: ${input.id}`);
          const missionActions = actions
            .findByEngagement(mission.engagementId)
            .filter((item) => item.missionId === mission.id);
          return {
            content: [
              { type: 'text', text: JSON.stringify({ mission, actions: missionActions }, null, 2) },
            ],
          };
        }
        const context = contexts.get(input.id, input.targetNodeIds ?? [], {
          edgeKinds: input.edgeKinds,
          depth: input.depth,
        });
        if (!context) throw new Error(`Action not found: ${input.id}`);
        return { content: [{ type: 'text', text: JSON.stringify(context, null, 2) }] };
      } catch (error) {
        return {
          content: [{ type: 'text', text: error instanceof Error ? error.message : String(error) }],
          isError: true,
        };
      }
    },
  );
}
