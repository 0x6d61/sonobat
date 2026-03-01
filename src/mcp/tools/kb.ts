/**
 * sonobat — MCP Knowledge Base Tools
 *
 * Tools for searching technique documentation (HackTricks knowledge base)
 * and managing the FTS5 index.
 *
 * Renamed from technique.ts:
 *   search_techniques -> search_kb
 *   index_hacktricks  -> index_kb
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { TechniqueDocRepository } from '../../db/repository/technique-doc-repository.js';
import { indexHacktricks } from '../../engine/indexer.js';

export function registerKbTools(server: McpServer, db: Database.Database): void {
  const repo = new TechniqueDocRepository(db);

  // 1. search_kb (renamed from search_techniques)
  server.tool(
    'search_kb',
    'Search the technique knowledge base (HackTricks) using full-text search. Returns relevant technique documentation chunks ranked by relevance.',
    {
      query: z.string().describe('Search query (e.g. "docker breakout", "SQL injection")'),
      category: z
        .string()
        .optional()
        .describe('Filter by category (e.g. "linux-hardening", "web")'),
      limit: z.number().optional().describe('Maximum number of results (default: 10)'),
    },
    async ({ query, category, limit }) => {
      const results = repo.search(query, { limit: limit ?? 10, category });

      if (results.length === 0) {
        return {
          content: [
            {
              type: 'text',
              text: `No results found for "${query}".${repo.count() === 0 ? ' The technique index is empty. Run index_kb to populate it.' : ''}`,
            },
          ],
        };
      }

      const formatted = results.map((r) => ({
        title: r.title,
        category: r.category,
        filePath: r.filePath,
        chunkIndex: r.chunkIndex,
        score: r.score,
        content: r.content,
      }));

      return { content: [{ type: 'text', text: JSON.stringify(formatted, null, 2) }] };
    },
  );

  // 2. index_kb (renamed from index_hacktricks)
  server.tool(
    'index_kb',
    'Index or re-index the HackTricks documentation into the full-text search database. This reads Markdown files from the data/hacktricks directory.',
    {
      path: z
        .string()
        .optional()
        .describe('Path to the HackTricks repository directory (default: data/hacktricks)'),
    },
    async ({ path: hacktricksPath }) => {
      const dir = hacktricksPath ?? 'data/hacktricks';

      try {
        const count = indexHacktricks(db, dir);
        return {
          content: [
            {
              type: 'text',
              text: `Successfully indexed ${count} technique documentation chunks from ${dir}.`,
            },
          ],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [{ type: 'text', text: `Failed to index HackTricks: ${message}` }],
          isError: true,
        };
      }
    },
  );
}
