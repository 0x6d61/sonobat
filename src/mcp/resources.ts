/**
 * sonobat — MCP Resources
 *
 * Read-only resources for browsing the AttackDataGraph.
 * Uses the graph-native nodes/edges schema.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { NodeRepository } from '../db/repository/node-repository.js';
import { EdgeRepository } from '../db/repository/edge-repository.js';
import { TechniqueDocRepository } from '../db/repository/technique-doc-repository.js';
import { NODE_KINDS } from '../types/graph.js';

export function registerResources(server: McpServer, db: Database.Database): void {
  const nodeRepo = new NodeRepository(db);
  const edgeRepo = new EdgeRepository(db);
  const techDocRepo = new TechniqueDocRepository(db);

  // 1. sonobat://nodes?kind=host — Node list (replaces sonobat://hosts)
  server.resource(
    'nodes',
    'sonobat://nodes',
    {
      description:
        'List of all nodes in the AttackDataGraph (optionally filter by kind via query param)',
    },
    async (uri) => {
      const kindParam = uri.searchParams?.get('kind');
      let nodes;
      if (kindParam && NODE_KINDS.includes(kindParam as (typeof NODE_KINDS)[number])) {
        nodes = nodeRepo.findByKind(kindParam as (typeof NODE_KINDS)[number]);
      } else {
        // Return all nodes (summary view)
        nodes = NODE_KINDS.flatMap((k) => nodeRepo.findByKind(k));
      }
      const result = nodes.map((n) => ({ ...n, props: JSON.parse(n.propsJson) }));
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: 'application/json',
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    },
  );

  // 2. sonobat://nodes/{id} — Node detail (replaces sonobat://hosts/{id})
  server.resource(
    'node-detail',
    'sonobat://nodes/{id}',
    { description: 'Detailed node with adjacent edges and neighbor nodes' },
    async (uri) => {
      const nodeId = uri.pathname.split('/').pop() ?? '';
      const node = nodeRepo.findById(nodeId);
      if (!node) {
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: JSON.stringify({ error: `Node not found: ${nodeId}` }),
            },
          ],
        };
      }

      const outEdges = edgeRepo.findBySource(node.id);
      const inEdges = edgeRepo.findByTarget(node.id);
      const adjacentNodeIds = new Set([
        ...outEdges.map((e) => e.targetId),
        ...inEdges.map((e) => e.sourceId),
      ]);
      const adjacentNodes = [...adjacentNodeIds]
        .map((nid) => nodeRepo.findById(nid))
        .filter(Boolean)
        .map((n) => ({ ...n!, props: JSON.parse(n!.propsJson) }));

      const result = {
        ...node,
        props: JSON.parse(node.propsJson),
        outEdges,
        inEdges,
        adjacentNodes,
      };
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: 'application/json',
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    },
  );

  // 3. sonobat://summary — Statistics summary
  server.resource(
    'summary',
    'sonobat://summary',
    { description: 'Summary statistics of the AttackDataGraph' },
    async () => {
      const nodeCounts: Record<string, number> = {};
      for (const k of NODE_KINDS) {
        nodeCounts[k] = nodeRepo.findByKind(k).length;
      }
      const edgeCount = (db.prepare('SELECT COUNT(*) AS cnt FROM edges').get() as { cnt: number })
        .cnt;
      const artifactCount = (
        db.prepare('SELECT COUNT(*) AS cnt FROM artifacts').get() as { cnt: number }
      ).cnt;

      return {
        contents: [
          {
            uri: 'sonobat://summary',
            mimeType: 'application/json',
            text: JSON.stringify(
              { nodes: nodeCounts, edges: edgeCount, artifacts: artifactCount },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // 4. sonobat://techniques/categories — Technique categories
  server.resource(
    'technique-categories',
    'sonobat://techniques/categories',
    { description: 'List of all technique documentation categories' },
    async () => {
      const categories = techDocRepo.listCategories();
      return {
        contents: [
          {
            uri: 'sonobat://techniques/categories',
            mimeType: 'application/json',
            text: JSON.stringify(categories, null, 2),
          },
        ],
      };
    },
  );
}
