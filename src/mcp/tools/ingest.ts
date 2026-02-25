/**
 * sonobat — MCP Ingest Tool
 *
 * Tool for ingesting tool output files into the AttackDataGraph.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { ingest } from '../../engine/ingest.js';

export function registerIngestTool(server: McpServer, db: Database.Database): void {
  server.tool(
    'ingest_file',
    'Ingest a tool output file (nmap XML, ffuf JSON, nuclei JSONL) into the AttackDataGraph',
    {
      path: z.string().describe('Absolute path to the tool output file'),
      tool: z.enum(['nmap', 'ffuf', 'nuclei']).describe('Tool that produced the output'),
    },
    async ({ path, tool }) => {
      try {
        const result = ingest(db, { path, tool });
        const nr = result.normalizeResult;
        const summary = [
          `Ingested ${tool} output from ${path}`,
          `Artifact ID: ${result.artifactId}`,
          `Created: ${nr.hostsCreated} hosts, ${nr.servicesCreated} services, ${nr.httpEndpointsCreated} endpoints, ${nr.inputsCreated} inputs, ${nr.observationsCreated} observations, ${nr.vulnerabilitiesCreated} vulnerabilities, ${nr.cvesCreated} CVEs`,
        ].join('\n');
        return { content: [{ type: 'text', text: summary }] };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { content: [{ type: 'text', text: `Ingest failed: ${message}` }], isError: true };
      }
    },
  );
}
