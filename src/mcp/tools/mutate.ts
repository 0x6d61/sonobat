/**
 * sonobat — MCP Mutate Tool (unified)
 *
 * Single 'mutate' tool with an 'action' parameter that replaces
 * all previous mutation tools (add_host, add_credential, etc.).
 *
 * Actions: add_node, add_edge, update_node, delete_node
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { NodeRepository } from '../../db/repository/node-repository.js';
import { EdgeRepository } from '../../db/repository/edge-repository.js';
import { NODE_KINDS, EDGE_KINDS, validateProps } from '../../types/graph.js';
import type { NodeKind, EdgeKind } from '../../types/graph.js';

/**
 * Get or create a singleton "manual" artifact for manual data entry.
 * Reused across all manual mutations to avoid artifact proliferation.
 * Uses direct SQL since ArtifactRepository is being removed.
 */
function getOrCreateManualArtifact(db: Database.Database): string {
  const row = db.prepare("SELECT id FROM artifacts WHERE tool = 'manual' LIMIT 1").get() as
    | { id: string }
    | undefined;
  if (row) return row.id;

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(
    "INSERT INTO artifacts (id, tool, kind, path, captured_at) VALUES (?, 'manual', 'manual_entry', 'manual', ?)",
  ).run(id, now);
  return id;
}

export function registerMutateTool(server: McpServer, db: Database.Database): void {
  const nodeRepo = new NodeRepository(db);
  const edgeRepo = new EdgeRepository(db);

  server.tool(
    'mutate',
    'Mutate the AttackDataGraph. Actions: add_node, add_edge, update_node, delete_node',
    {
      action: z.enum(['add_node', 'add_edge', 'update_node', 'delete_node']),
      // Parameters for add_node
      kind: z.string().optional().describe('Node kind (host, service, endpoint, etc.)'),
      propsJson: z
        .string()
        .optional()
        .describe(
          'Node properties as JSON string (e.g. {"authorityKind":"IP","authority":"10.0.0.1","resolvedIpsJson":"[]"})',
        ),
      parentId: z
        .string()
        .optional()
        .describe('Parent node ID (required for service, endpoint, input, vhost, cve)'),
      // Parameters for add_edge
      edgeKind: z.string().optional().describe('Edge kind (HOST_SERVICE, SERVICE_ENDPOINT, etc.)'),
      sourceId: z.string().optional().describe('Source node ID for edge'),
      targetId: z.string().optional().describe('Target node ID for edge'),
      // Parameters for update_node / delete_node
      id: z.string().optional().describe('Node ID for update or delete'),
      // Common optional
      evidenceArtifactId: z
        .string()
        .optional()
        .describe('Evidence artifact ID. If omitted, a "manual" artifact is auto-created/reused.'),
    },
    async ({
      action,
      kind,
      propsJson: propsJsonStr,
      parentId,
      edgeKind,
      sourceId,
      targetId,
      id,
      evidenceArtifactId,
    }) => {
      // Parse propsJson string into an object when provided
      let props: Record<string, unknown> | undefined;
      if (propsJsonStr) {
        try {
          props = JSON.parse(propsJsonStr) as Record<string, unknown>;
        } catch {
          return {
            content: [{ type: 'text', text: `Invalid JSON in propsJson: ${propsJsonStr}` }],
            isError: true,
          };
        }
      }

      switch (action) {
        // ----------------------------------------------------------------
        // add_node
        // ----------------------------------------------------------------
        case 'add_node': {
          if (!kind) {
            return {
              content: [{ type: 'text', text: 'kind parameter is required for add_node' }],
              isError: true,
            };
          }
          if (!NODE_KINDS.includes(kind as NodeKind)) {
            return {
              content: [
                {
                  type: 'text',
                  text: `Invalid kind: ${kind}. Valid kinds: ${NODE_KINDS.join(', ')}`,
                },
              ],
              isError: true,
            };
          }
          if (!props) {
            return {
              content: [{ type: 'text', text: 'propsJson parameter is required for add_node' }],
              isError: true,
            };
          }

          // Validate props against the schema for this kind
          const validation = validateProps(kind as NodeKind, props);
          if (!validation.ok) {
            return {
              content: [
                {
                  type: 'text',
                  text: `Props validation failed for kind="${kind}": ${validation.error}`,
                },
              ],
              isError: true,
            };
          }

          const artifactId = evidenceArtifactId ?? getOrCreateManualArtifact(db);
          const { node, created } = nodeRepo.upsert(kind as NodeKind, props, artifactId, parentId);
          const result = {
            ...node,
            props: JSON.parse(node.propsJson),
            created,
          };
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }

        // ----------------------------------------------------------------
        // add_edge
        // ----------------------------------------------------------------
        case 'add_edge': {
          if (!edgeKind) {
            return {
              content: [{ type: 'text', text: 'edgeKind parameter is required for add_edge' }],
              isError: true,
            };
          }
          if (!EDGE_KINDS.includes(edgeKind as EdgeKind)) {
            return {
              content: [
                {
                  type: 'text',
                  text: `Invalid edgeKind: ${edgeKind}. Valid kinds: ${EDGE_KINDS.join(', ')}`,
                },
              ],
              isError: true,
            };
          }
          if (!sourceId) {
            return {
              content: [{ type: 'text', text: 'sourceId parameter is required for add_edge' }],
              isError: true,
            };
          }
          if (!targetId) {
            return {
              content: [{ type: 'text', text: 'targetId parameter is required for add_edge' }],
              isError: true,
            };
          }

          const artifactId = evidenceArtifactId ?? getOrCreateManualArtifact(db);
          const { edge, created } = edgeRepo.upsert(
            edgeKind as EdgeKind,
            sourceId,
            targetId,
            artifactId,
          );
          return {
            content: [{ type: 'text', text: JSON.stringify({ ...edge, created }, null, 2) }],
          };
        }

        // ----------------------------------------------------------------
        // update_node
        // ----------------------------------------------------------------
        case 'update_node': {
          if (!id) {
            return {
              content: [{ type: 'text', text: 'id parameter is required for update_node' }],
              isError: true,
            };
          }
          if (!props) {
            return {
              content: [{ type: 'text', text: 'propsJson parameter is required for update_node' }],
              isError: true,
            };
          }

          // Find existing node to get its kind and current props
          const existing = nodeRepo.findById(id);
          if (!existing) {
            return {
              content: [{ type: 'text', text: `Node not found: ${id}` }],
              isError: true,
            };
          }

          // Merge existing props with the partial update
          const existingProps = JSON.parse(existing.propsJson) as Record<string, unknown>;
          const mergedProps = { ...existingProps, ...props };

          // Validate merged props
          const validation = validateProps(existing.kind, mergedProps);
          if (!validation.ok) {
            return {
              content: [
                {
                  type: 'text',
                  text: `Props validation failed for kind="${existing.kind}": ${validation.error}`,
                },
              ],
              isError: true,
            };
          }

          const updated = nodeRepo.updateProps(id, mergedProps);
          if (!updated) {
            return {
              content: [{ type: 'text', text: `Failed to update node: ${id}` }],
              isError: true,
            };
          }
          const result = { ...updated, props: JSON.parse(updated.propsJson) };
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }

        // ----------------------------------------------------------------
        // delete_node
        // ----------------------------------------------------------------
        case 'delete_node': {
          if (!id) {
            return {
              content: [{ type: 'text', text: 'id parameter is required for delete_node' }],
              isError: true,
            };
          }

          const deleted = nodeRepo.delete(id);
          if (!deleted) {
            return {
              content: [{ type: 'text', text: `Node not found: ${id}` }],
              isError: true,
            };
          }
          return {
            content: [{ type: 'text', text: `Node ${id} deleted successfully.` }],
          };
        }
      }
    },
  );
}
