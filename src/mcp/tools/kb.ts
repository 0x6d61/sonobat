/**
 * sonobat — MCP Knowledge Base Tools
 *
 * Tools for searching technique documentation (HackTricks knowledge base)
 * and managing the FTS5 index.
 *
 * Features:
 *   - search_kb: Full-text search with BM25 ranking
 *   - index_kb: Auto-clone/pull HackTricks + incremental indexing
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import fs from 'node:fs';
import { z } from 'zod';
import { TechniqueDocRepository } from '../../db/repository/technique-doc-repository.js';
import { indexHacktricks } from '../../engine/indexer.js';
import { getHacktricksDir, ensureDataDir } from '../../engine/data-dir.js';
import { cloneHacktricks, pullHacktricks, isGitAvailable } from '../../engine/git-ops.js';
import type { IndexResult } from '../../engine/indexer.js';

/**
 * Format an IndexResult into a human-readable message.
 */
function formatIndexResult(result: IndexResult, dir: string): string {
  const lines: string[] = [
    `Successfully indexed from ${dir}.`,
    `  Chunks inserted: ${result.totalChunks}`,
    `  New files: ${result.newFiles}`,
    `  Updated files: ${result.updatedFiles}`,
    `  Deleted files: ${result.deletedFiles}`,
    `  Skipped (unchanged): ${result.skippedFiles}`,
  ];
  return lines.join('\n');
}

export function registerKbTools(server: McpServer, db: Database.Database): void {
  const repo = new TechniqueDocRepository(db);

  // 1. search_kb
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

  // 2. index_kb (with auto-clone/pull)
  server.tool(
    'index_kb',
    'Index or re-index the HackTricks documentation into the full-text search database. When called without a path, automatically clones or updates HackTricks from GitHub. Uses incremental indexing to skip unchanged files.',
    {
      path: z
        .string()
        .optional()
        .describe(
          'Path to the HackTricks repository directory. If omitted, auto-clones to ~/.sonobat/data/hacktricks/',
        ),
      update: z
        .boolean()
        .optional()
        .describe(
          'Whether to pull latest changes before indexing (default: true). Set to false to skip git pull.',
        ),
    },
    async ({ path: hacktricksPath, update }) => {
      try {
        let dir: string;
        const messages: string[] = [];

        if (hacktricksPath) {
          // Explicit path provided — use as-is
          dir = hacktricksPath;
        } else {
          // Auto-clone/pull flow
          dir = getHacktricksDir();
          ensureDataDir();

          if (!fs.existsSync(dir)) {
            // Directory doesn't exist → clone
            const gitAvailable = await isGitAvailable();
            if (!gitAvailable) {
              return {
                content: [
                  {
                    type: 'text',
                    text: 'git is not installed or not in PATH. Please install git and try again, or provide a path to an existing HackTricks directory.',
                  },
                ],
                isError: true,
              };
            }

            messages.push(`Cloning HackTricks to ${dir}...`);
            const cloneResult = await cloneHacktricks(dir);
            if (!cloneResult.ok) {
              return {
                content: [
                  {
                    type: 'text',
                    text: `Failed to clone HackTricks: ${cloneResult.error.message}${cloneResult.error.cause ? ` (${cloneResult.error.cause})` : ''}`,
                  },
                ],
                isError: true,
              };
            }
            messages.push('Clone completed.');
          } else if (update !== false) {
            // Directory exists → pull (failure is a warning, not an error)
            const pullResult = await pullHacktricks(dir);
            if (pullResult.ok) {
              messages.push(`Updated: ${pullResult.message}`);
            } else {
              messages.push(
                `Warning: git pull failed (${pullResult.error.message}). Continuing with existing data.`,
              );
            }
          }
        }

        const result = indexHacktricks(db, dir);
        messages.push(formatIndexResult(result, dir));

        return {
          content: [{ type: 'text', text: messages.join('\n') }],
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
