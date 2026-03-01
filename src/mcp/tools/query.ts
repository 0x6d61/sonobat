/**
 * sonobat — MCP Query Tool (unified)
 *
 * Single 'query' tool with an 'action' parameter that replaces
 * all previous read-only tools (list_hosts, get_host, list_services, etc.).
 *
 * Actions: list_nodes, get_node, traverse, summary, attack_paths
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { NodeRepository } from '../../db/repository/node-repository.js';
import { EdgeRepository } from '../../db/repository/edge-repository.js';
import { GraphQueryRepository } from '../../db/repository/graph-query-repository.js';
import { NODE_KINDS, EDGE_KINDS } from '../../types/graph.js';
import type { NodeKind, EdgeKind } from '../../types/graph.js';

export function registerQueryTool(server: McpServer, db: Database.Database): void {
  const nodeRepo = new NodeRepository(db);
  const edgeRepo = new EdgeRepository(db);
  const graphQueryRepo = new GraphQueryRepository(db);

  server.tool(
    'query',
    'Query the AttackDataGraph. Actions: list_nodes, get_node, traverse, summary, attack_paths',
    {
      action: z.enum(['list_nodes', 'get_node', 'traverse', 'summary', 'attack_paths']),
      // Parameters for list_nodes
      kind: z.string().optional().describe('Node kind filter (host, service, endpoint, etc.)'),
      // Parameters for get_node
      id: z.string().optional().describe('Node ID'),
      // Parameters for traverse
      startId: z.string().optional().describe('Start node ID for traversal'),
      depth: z.number().optional().describe('Max traversal depth'),
      edgeKinds: z.array(z.string()).optional().describe('Edge kinds to follow'),
      // Parameters for attack_paths
      pattern: z.string().optional().describe('Preset pattern name'),
      // Common filters
      filtersJson: z
        .string()
        .optional()
        .describe('Filters as JSON object for list_nodes (JSON_EXTRACT on props)'),
    },
    async ({ action, kind, id, startId, depth, edgeKinds, pattern, filtersJson }) => {
      switch (action) {
        case 'list_nodes': {
          if (!kind) {
            return {
              content: [{ type: 'text', text: 'kind parameter required for list_nodes' }],
              isError: true,
            };
          }
          // Validate kind
          if (!NODE_KINDS.includes(kind as NodeKind)) {
            return {
              content: [
                {
                  type: 'text',
                  text: `Invalid kind: ${kind}. Valid: ${NODE_KINDS.join(', ')}`,
                },
              ],
              isError: true,
            };
          }
          const filters = filtersJson
            ? (JSON.parse(filtersJson) as Record<string, unknown>)
            : undefined;
          const nodes = nodeRepo.findByKind(kind as NodeKind, filters);
          const result = nodes.map((n) => ({ ...n, props: JSON.parse(n.propsJson) }));
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }
        case 'get_node': {
          if (!id) {
            return {
              content: [{ type: 'text', text: 'id parameter required for get_node' }],
              isError: true,
            };
          }
          const node = nodeRepo.findById(id);
          if (!node) {
            return {
              content: [{ type: 'text', text: `Node not found: ${id}` }],
              isError: true,
            };
          }
          // Get adjacent edges and nodes
          const outEdges = edgeRepo.findBySource(node.id);
          const inEdges = edgeRepo.findByTarget(node.id);
          const adjacentNodeIds = new Set([
            ...outEdges.map((e) => e.targetId),
            ...inEdges.map((e) => e.sourceId),
          ]);
          const adjacentNodes = [...adjacentNodeIds]
            .map((nid) => nodeRepo.findById(nid))
            .filter(Boolean);
          const result = {
            ...node,
            props: JSON.parse(node.propsJson),
            outEdges,
            inEdges,
            adjacentNodes: adjacentNodes.map((n) => ({
              ...n!,
              props: JSON.parse(n!.propsJson),
            })),
          };
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }
        case 'traverse': {
          if (!startId) {
            return {
              content: [{ type: 'text', text: 'startId parameter required for traverse' }],
              isError: true,
            };
          }
          const validEdgeKinds = edgeKinds?.filter((ek) => EDGE_KINDS.includes(ek as EdgeKind)) as
            | EdgeKind[]
            | undefined;
          const results = graphQueryRepo.traverse(startId, depth, validEdgeKinds);
          const enriched = results.map((r) => ({
            ...r,
            node: { ...r.node, props: JSON.parse(r.node.propsJson) },
          }));
          return { content: [{ type: 'text', text: JSON.stringify(enriched, null, 2) }] };
        }
        case 'summary': {
          // Count nodes by kind and edges by kind
          const nodeCounts: Record<string, number> = {};
          for (const k of NODE_KINDS) {
            nodeCounts[k] = nodeRepo.findByKind(k).length;
          }
          const edgeCounts: Record<string, number> = {};
          for (const ek of EDGE_KINDS) {
            edgeCounts[ek] = edgeRepo.findByKind(ek).length;
          }
          // Also count artifacts
          const artifactCount = (
            db.prepare('SELECT COUNT(*) AS cnt FROM artifacts').get() as { cnt: number }
          ).cnt;
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  { nodes: nodeCounts, edges: edgeCounts, artifacts: artifactCount },
                  null,
                  2,
                ),
              },
            ],
          };
        }
        case 'attack_paths': {
          if (!pattern) {
            return {
              content: [{ type: 'text', text: 'pattern parameter required for attack_paths' }],
              isError: true,
            };
          }
          try {
            const results = graphQueryRepo.runPreset(pattern);
            return { content: [{ type: 'text', text: JSON.stringify(results, null, 2) }] };
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return {
              content: [{ type: 'text', text: `attack_paths error: ${message}` }],
              isError: true,
            };
          }
        }
      }
    },
  );
}
