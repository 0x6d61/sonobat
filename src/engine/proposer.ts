/**
 * sonobat — Proposer engine
 *
 * Analyzes the AttackDataGraph stored in SQLite and proposes
 * next-step actions (scans, discovery, etc.) based on missing data.
 */

import type Database from 'better-sqlite3';
import type { Action } from '../types/engine.js';
import { HostRepository } from '../db/repository/host-repository.js';
import { ServiceRepository } from '../db/repository/service-repository.js';
import { HttpEndpointRepository } from '../db/repository/http-endpoint-repository.js';
import { InputRepository } from '../db/repository/input-repository.js';
import { ObservationRepository } from '../db/repository/observation-repository.js';
import { VhostRepository } from '../db/repository/vhost-repository.js';
import { VulnerabilityRepository } from '../db/repository/vulnerability-repository.js';
import type { Host, Service } from '../types/entities.js';

/**
 * Analyze the database for missing reconnaissance data and return
 * a list of proposed actions to fill the gaps.
 *
 * @param db      - The better-sqlite3 database instance
 * @param hostId  - Optional: limit analysis to a single host
 * @returns Array of proposed actions
 */
export function propose(db: Database.Database, hostId?: string): Action[] {
  const hostRepo = new HostRepository(db);
  const serviceRepo = new ServiceRepository(db);
  const httpEndpointRepo = new HttpEndpointRepository(db);
  const inputRepo = new InputRepository(db);
  const observationRepo = new ObservationRepository(db);
  const vhostRepo = new VhostRepository(db);
  const vulnRepo = new VulnerabilityRepository(db);

  const actions: Action[] = [];

  // Determine target hosts
  let hosts: Host[];
  if (hostId !== undefined) {
    const host = hostRepo.findById(hostId);
    if (host === undefined) {
      return [];
    }
    hosts = [host];
  } else {
    hosts = hostRepo.findAll();
  }

  for (const host of hosts) {
    const services = serviceRepo.findByHostId(host.id);

    // (a) No services at all -> suggest nmap scan
    if (services.length === 0) {
      actions.push({
        kind: 'nmap_scan',
        description: `Port scan ${host.authority} to discover services`,
        command: `nmap -p- -sV ${host.authority}`,
        params: { hostId: host.id },
      });
      continue;
    }

    // (b) For each HTTP/HTTPS service, check for missing data
    for (const service of services) {
      if (service.appProto !== 'http' && service.appProto !== 'https') {
        continue;
      }

      const baseUri = `${service.appProto}://${host.authority}:${service.port}`;

      proposeForHttpService(
        actions,
        host,
        service,
        baseUri,
        httpEndpointRepo,
        inputRepo,
        observationRepo,
        vhostRepo,
        vulnRepo,
      );
    }
  }

  return actions;
}

/**
 * Check a single HTTP/HTTPS service for missing data and push
 * proposed actions into the actions array.
 */
function proposeForHttpService(
  actions: Action[],
  host: Host,
  service: Service,
  baseUri: string,
  httpEndpointRepo: HttpEndpointRepository,
  inputRepo: InputRepository,
  observationRepo: ObservationRepository,
  vhostRepo: VhostRepository,
  vulnRepo: VulnerabilityRepository,
): void {
  const endpoints = httpEndpointRepo.findByServiceId(service.id);

  // No endpoints -> suggest directory/file discovery
  if (endpoints.length === 0) {
    actions.push({
      kind: 'ffuf_discovery',
      description: `Discover endpoints on ${baseUri}`,
      command: `ffuf -u ${baseUri}/FUZZ -w /usr/share/wordlists/dirb/common.txt`,
      params: { hostId: host.id, serviceId: service.id },
    });
  }

  // For each endpoint: check inputs
  for (const endpoint of endpoints) {
    const inputs = inputRepo.findByServiceId(service.id);

    if (inputs.length === 0) {
      actions.push({
        kind: 'parameter_discovery',
        description: `Discover input parameters for ${baseUri}${endpoint.path}`,
        params: { hostId: host.id, serviceId: service.id, endpointId: endpoint.id },
      });
    }

    // For each input: check observations
    for (const input of inputs) {
      const observations = observationRepo.findByInputId(input.id);

      if (observations.length === 0) {
        actions.push({
          kind: 'value_collection',
          description: `Collect observed values for input "${input.name}" (${input.location})`,
          params: {
            hostId: host.id,
            serviceId: service.id,
            endpointId: endpoint.id,
            inputId: input.id,
          },
        });
      }
    }
  }

  // Check vhosts
  const vhosts = vhostRepo.findByHostId(host.id);
  if (vhosts.length === 0) {
    actions.push({
      kind: 'vhost_discovery',
      description: `Discover virtual hosts for ${host.authority}`,
      params: { hostId: host.id, serviceId: service.id },
    });
  }

  // Check vulnerabilities
  const vulns = vulnRepo.findByServiceId(service.id);
  if (vulns.length === 0) {
    actions.push({
      kind: 'nuclei_scan',
      description: `Scan ${baseUri} for known vulnerabilities`,
      command: `nuclei -u ${baseUri} -jsonl`,
      params: { hostId: host.id, serviceId: service.id },
    });
  }
}
