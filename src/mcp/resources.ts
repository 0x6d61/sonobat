/**
 * sonobat — MCP Resources
 *
 * Read-only resources for browsing the AttackDataGraph.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { HostRepository } from '../db/repository/host-repository.js';
import { ServiceRepository } from '../db/repository/service-repository.js';
import { VhostRepository } from '../db/repository/vhost-repository.js';
import { HttpEndpointRepository } from '../db/repository/http-endpoint-repository.js';
import { InputRepository } from '../db/repository/input-repository.js';
import { VulnerabilityRepository } from '../db/repository/vulnerability-repository.js';
import { TechniqueDocRepository } from '../db/repository/technique-doc-repository.js';

export function registerResources(server: McpServer, db: Database.Database): void {
  const hostRepo = new HostRepository(db);
  const serviceRepo = new ServiceRepository(db);
  const vhostRepo = new VhostRepository(db);
  const httpEndpointRepo = new HttpEndpointRepository(db);
  const inputRepo = new InputRepository(db);
  const vulnRepo = new VulnerabilityRepository(db);
  const techDocRepo = new TechniqueDocRepository(db);

  // 1. sonobat://hosts — Host list
  server.resource(
    'hosts',
    'sonobat://hosts',
    { description: 'List of all discovered hosts' },
    async () => {
      const hosts = hostRepo.findAll();
      return {
        contents: [
          {
            uri: 'sonobat://hosts',
            mimeType: 'application/json',
            text: JSON.stringify(hosts, null, 2),
          },
        ],
      };
    },
  );

  // 2. sonobat://hosts/{id} — Host detail tree
  server.resource(
    'host-detail',
    'sonobat://hosts/{id}',
    { description: 'Detailed host tree with services, endpoints, inputs, and vulnerabilities' },
    async (uri) => {
      // Extract host ID from the URI
      const hostId = uri.pathname.split('/').pop() ?? '';
      const host = hostRepo.findById(hostId);
      if (!host) {
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: JSON.stringify({ error: `Host not found: ${hostId}` }),
            },
          ],
        };
      }

      const services = serviceRepo.findByHostId(hostId);
      const vhosts = vhostRepo.findByHostId(hostId);

      const serviceTree = services.map((service) => {
        const endpoints = httpEndpointRepo.findByServiceId(service.id);
        const inputs = inputRepo.findByServiceId(service.id);
        const vulnerabilities = vulnRepo.findByServiceId(service.id);
        return { ...service, endpoints, inputs, vulnerabilities };
      });

      const result = { ...host, services: serviceTree, vhosts };
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
      // Use direct SQL COUNT queries for efficiency
      const counts: Record<string, number> = {};
      const tables = [
        'hosts',
        'services',
        'http_endpoints',
        'inputs',
        'observations',
        'credentials',
        'vulnerabilities',
        'cves',
        'vhosts',
        'artifacts',
      ];

      for (const table of tables) {
        const row = db.prepare(`SELECT COUNT(*) as count FROM ${table}`).get() as { count: number };
        counts[table] = row.count;
      }

      return {
        contents: [
          {
            uri: 'sonobat://summary',
            mimeType: 'application/json',
            text: JSON.stringify(counts, null, 2),
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
