/**
 * sonobat — MCP Query Tools
 *
 * Read-only tools for querying the AttackDataGraph.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { HostRepository } from '../../db/repository/host-repository.js';
import { ServiceRepository } from '../../db/repository/service-repository.js';
import { VhostRepository } from '../../db/repository/vhost-repository.js';
import { HttpEndpointRepository } from '../../db/repository/http-endpoint-repository.js';
import { InputRepository } from '../../db/repository/input-repository.js';
import { ObservationRepository } from '../../db/repository/observation-repository.js';
import { CredentialRepository } from '../../db/repository/credential-repository.js';
import { VulnerabilityRepository } from '../../db/repository/vulnerability-repository.js';

export function registerQueryTools(server: McpServer, db: Database.Database): void {
  const hostRepo = new HostRepository(db);
  const serviceRepo = new ServiceRepository(db);
  const vhostRepo = new VhostRepository(db);
  const httpEndpointRepo = new HttpEndpointRepository(db);
  const inputRepo = new InputRepository(db);
  const observationRepo = new ObservationRepository(db);
  const credentialRepo = new CredentialRepository(db);
  const vulnRepo = new VulnerabilityRepository(db);

  // 1. list_hosts
  server.tool('list_hosts', 'List all discovered hosts', {}, async () => {
    const hosts = hostRepo.findAll();
    return { content: [{ type: 'text', text: JSON.stringify(hosts, null, 2) }] };
  });

  // 2. get_host
  server.tool(
    'get_host',
    'Get detailed information about a host including services and vhosts',
    { hostId: z.string().describe('Host UUID') },
    async ({ hostId }) => {
      const host = hostRepo.findById(hostId);
      if (!host) {
        return { content: [{ type: 'text', text: `Host not found: ${hostId}` }], isError: true };
      }
      const services = serviceRepo.findByHostId(hostId);
      const vhosts = vhostRepo.findByHostId(hostId);
      const result = { ...host, services, vhosts };
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    },
  );

  // 3. list_services
  server.tool(
    'list_services',
    'List all services for a host',
    { hostId: z.string().describe('Host UUID') },
    async ({ hostId }) => {
      const services = serviceRepo.findByHostId(hostId);
      return { content: [{ type: 'text', text: JSON.stringify(services, null, 2) }] };
    },
  );

  // 4. list_endpoints
  server.tool(
    'list_endpoints',
    'List all HTTP endpoints for a service',
    { serviceId: z.string().describe('Service UUID') },
    async ({ serviceId }) => {
      const endpoints = httpEndpointRepo.findByServiceId(serviceId);
      return { content: [{ type: 'text', text: JSON.stringify(endpoints, null, 2) }] };
    },
  );

  // 5. list_inputs
  server.tool(
    'list_inputs',
    'List all input parameters for a service, optionally filtered by location',
    {
      serviceId: z.string().describe('Service UUID'),
      location: z
        .string()
        .optional()
        .describe('Filter by location (query, path, body, header, cookie)'),
    },
    async ({ serviceId, location }) => {
      const inputs = inputRepo.findByServiceId(serviceId, location);
      return { content: [{ type: 'text', text: JSON.stringify(inputs, null, 2) }] };
    },
  );

  // 6. list_observations
  server.tool(
    'list_observations',
    'List all observations for an input parameter',
    { inputId: z.string().describe('Input UUID') },
    async ({ inputId }) => {
      const observations = observationRepo.findByInputId(inputId);
      return { content: [{ type: 'text', text: JSON.stringify(observations, null, 2) }] };
    },
  );

  // 7. list_credentials
  server.tool(
    'list_credentials',
    'List credentials, optionally filtered by service',
    {
      serviceId: z.string().optional().describe('Service UUID (optional, omit to list all)'),
    },
    async ({ serviceId }) => {
      const credentials = serviceId
        ? credentialRepo.findByServiceId(serviceId)
        : credentialRepo.findAll();
      return { content: [{ type: 'text', text: JSON.stringify(credentials, null, 2) }] };
    },
  );

  // 8. list_vulnerabilities
  server.tool(
    'list_vulnerabilities',
    'List vulnerabilities, optionally filtered by service, severity, and/or status',
    {
      serviceId: z.string().optional().describe('Service UUID (optional, omit to list all)'),
      severity: z
        .string()
        .optional()
        .describe('Filter by severity (critical, high, medium, low, info)'),
      status: z
        .string()
        .optional()
        .describe('Filter by status (unverified, confirmed, false_positive, not_exploitable)'),
    },
    async ({ serviceId, severity, status }) => {
      const vulns = serviceId
        ? vulnRepo.findByServiceId(serviceId, severity, status)
        : vulnRepo.findAll(severity, status);
      return { content: [{ type: 'text', text: JSON.stringify(vulns, null, 2) }] };
    },
  );
}
