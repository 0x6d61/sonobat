/**
 * sonobat — MCP Datalog Tools
 *
 * Tools for querying and analyzing the AttackDataGraph using
 * the Datalog inference engine.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import {
  listFacts,
  runDatalog,
  queryAttackPaths,
  listPatterns,
} from '../../engine/datalog/index.js';
import type { Fact, EvalResult } from '../../engine/datalog/types.js';

/**
 * Format a single Fact as Datalog-style text.
 *
 * Example: host("abc-123", "10.0.0.1", "IP").
 */
function formatFact(fact: Fact): string {
  const args = fact.values.map((v) => (typeof v === 'number' ? String(v) : `"${v}"`)).join(', ');
  return `${fact.predicate}(${args}).`;
}

/**
 * Format an EvalResult as human-readable text.
 */
function formatEvalResult(result: EvalResult): string {
  if (result.answers.length === 0) {
    return `No query results.\n\nStats: ${result.stats.iterations} iterations, ${result.stats.totalDerived} derived facts, ${result.stats.elapsedMs}ms`;
  }

  const sections: string[] = [];

  for (const answer of result.answers) {
    const queryArgs = answer.query.args
      .map((a) => (a.kind === 'variable' ? a.name : a.kind === 'constant' ? String(a.value) : '_'))
      .join(', ');
    const header = `Query: ${answer.query.predicate}(${queryArgs})`;

    if (answer.tuples.length === 0) {
      sections.push(`${header}\nResults: (empty)`);
      continue;
    }

    const columns = answer.columns;

    // Calculate column widths
    const widths = columns.map((col, i) =>
      Math.max(col.length, ...answer.tuples.map((t) => String(t[i]).length)),
    );

    // Header row
    const headerRow = columns.map((col, i) => col.padEnd(widths[i])).join(' | ');

    // Data rows
    const dataRows = answer.tuples.map(
      (tuple) => '  ' + tuple.map((val, i) => String(val).padEnd(widths[i])).join(' | '),
    );

    sections.push(
      `${header}\nResults (${answer.tuples.length} rows):\n  ${headerRow}\n${dataRows.join('\n')}`,
    );
  }

  sections.push(
    `\nStats: ${result.stats.iterations} iterations, ${result.stats.totalDerived} derived facts, ${result.stats.elapsedMs}ms`,
  );

  return sections.join('\n\n');
}

/**
 * Register Datalog-related MCP tools on the server.
 */
export function registerDatalogTools(server: McpServer, db: Database.Database): void {
  // 1. list_facts
  server.tool(
    'list_facts',
    'List database contents as Datalog facts. Optionally filter by predicate name and limit the number of results.',
    {
      predicate: z
        .string()
        .optional()
        .describe(
          'Filter by predicate name (host, service, http_endpoint, input, endpoint_input, observation, credential, vulnerability, vulnerability_endpoint, cve, vhost)',
        ),
      limit: z.number().optional().describe('Maximum number of facts to return'),
    },
    async ({ predicate, limit }) => {
      const facts = listFacts(db, predicate, limit);
      if (facts.length === 0) {
        return {
          content: [{ type: 'text', text: 'No facts found.' }],
        };
      }
      const text = facts.map(formatFact).join('\n');
      return { content: [{ type: 'text', text }] };
    },
  );

  // 2. run_datalog
  server.tool(
    'run_datalog',
    'Execute a custom Datalog program against the AttackDataGraph. Supports rules with :- and queries with ?-. Optionally save the program as a named rule for future reuse.',
    {
      program: z.string().describe('Datalog program text (rules and queries)'),
      save_name: z
        .string()
        .optional()
        .describe('Save the program as a named rule for future reuse'),
      save_description: z.string().optional().describe('Description of the saved rule'),
      generated_by: z
        .string()
        .optional()
        .describe('Who generated this rule: "human" or "ai" (default: "ai")'),
    },
    async ({ program, save_name, save_description, generated_by }) => {
      try {
        const generatedBy = generated_by === 'human' ? 'human' : 'ai';
        const result = runDatalog(db, program, {
          saveName: save_name,
          saveDescription: save_description,
          generatedBy,
        });
        const text = formatEvalResult(result);
        return { content: [{ type: 'text', text }] };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          content: [{ type: 'text', text: `Datalog error: ${message}` }],
          isError: true,
        };
      }
    },
  );

  // 3. query_attack_paths
  server.tool(
    'query_attack_paths',
    'Run a preset or saved attack pattern query. Use pattern "list" to see all available patterns.',
    {
      pattern: z
        .string()
        .describe(
          'Pattern name (e.g. "reachable_services", "critical_vulns") or "list" to see available patterns',
        ),
    },
    async ({ pattern }) => {
      if (pattern === 'list') {
        const patterns = listPatterns(db);
        if (patterns.length === 0) {
          return {
            content: [{ type: 'text', text: 'No patterns available.' }],
          };
        }
        const lines = patterns.map(
          (p) =>
            `- ${p.name} [${p.source}]${p.description ? `: ${p.description}` : ''}${p.generatedBy ? ` (by ${p.generatedBy})` : ''}`,
        );
        return {
          content: [
            {
              type: 'text',
              text: `Available patterns:\n${lines.join('\n')}`,
            },
          ],
        };
      }

      try {
        const result = queryAttackPaths(db, pattern);
        const text = formatEvalResult(result);
        return { content: [{ type: 'text', text }] };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          content: [{ type: 'text', text: `Datalog error: ${message}` }],
          isError: true,
        };
      }
    },
  );
}
