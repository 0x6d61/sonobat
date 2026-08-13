import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { ObservationRepository } from '../../db/repository/observation-repository.js';

export function registerObservationTool(server: McpServer, db: Database.Database): void {
  const observations = new ObservationRepository(db);
  server.tool(
    'observe',
    'Record an artifact interpretation and atomically apply graph changes',
    {
      artifactId: z.string(),
      actor: z.string(),
      contentJson: z.string(),
      confidence: z.number().min(0).max(1).optional(),
      nodesJson: z.string().optional(),
      edgesJson: z.string().optional(),
      findingIds: z.array(z.string()).optional(),
    },
    async (input) => {
      try {
        const result = observations.record({
          artifactId: input.artifactId,
          actor: input.actor,
          content: JSON.parse(input.contentJson) as unknown,
          confidence: input.confidence,
          nodes: input.nodesJson === undefined ? [] : (JSON.parse(input.nodesJson) as never[]),
          edges: input.edgesJson === undefined ? [] : (JSON.parse(input.edgesJson) as never[]),
          findingIds: input.findingIds ?? [],
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
