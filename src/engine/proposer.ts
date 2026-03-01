/**
 * sonobat — Proposer engine (graph-native)
 *
 * Analyzes the AttackDataGraph stored in SQLite and proposes
 * next-step actions (scans, discovery, etc.) based on missing data.
 *
 * Uses NodeRepository + EdgeRepository instead of entity-specific repositories.
 */

import type Database from 'better-sqlite3';
import type { Action } from '../types/engine.js';
import type { GraphNode } from '../types/graph.js';
import { NodeRepository } from '../db/repository/node-repository.js';
import { EdgeRepository } from '../db/repository/edge-repository.js';

/** Helper: parse propsJson safely */
function parseProps(node: GraphNode): Record<string, unknown> {
  return JSON.parse(node.propsJson) as Record<string, unknown>;
}

/**
 * Analyze the database for missing reconnaissance data and return
 * a list of proposed actions to fill the gaps.
 *
 * @param db      - The better-sqlite3 database instance
 * @param hostId  - Optional: limit analysis to a single host
 * @returns Array of proposed actions
 */
export function propose(db: Database.Database, hostId?: string): Action[] {
  const nodeRepo = new NodeRepository(db);
  const edgeRepo = new EdgeRepository(db);

  const actions: Action[] = [];

  // Determine target hosts
  let hosts: GraphNode[];
  if (hostId !== undefined) {
    const host = nodeRepo.findById(hostId);
    if (host === undefined) {
      return [];
    }
    hosts = [host];
  } else {
    hosts = nodeRepo.findByKind('host');
  }

  for (const host of hosts) {
    const hostProps = parseProps(host);
    const authority = hostProps.authority as string;

    // Find services: edges from host where kind='HOST_SERVICE' -> target nodes
    const serviceEdges = edgeRepo.findBySource(host.id, 'HOST_SERVICE');

    // (a) No services at all -> suggest nmap scan
    if (serviceEdges.length === 0) {
      actions.push({
        kind: 'nmap_scan',
        description: `Port scan ${authority} to discover services`,
        command: `nmap -p- -sV ${authority}`,
        params: { hostId: host.id },
      });
      continue;
    }

    // (b) For each HTTP/HTTPS service, check for missing data
    for (const serviceEdge of serviceEdges) {
      const serviceNode = nodeRepo.findById(serviceEdge.targetId);
      if (serviceNode === undefined) {
        continue;
      }

      const serviceProps = parseProps(serviceNode);
      const appProto = serviceProps.appProto as string;
      const port = serviceProps.port as number;

      if (appProto !== 'http' && appProto !== 'https') {
        continue;
      }

      const baseUri = `${appProto}://${authority}:${port}`;

      proposeForHttpService(actions, host, serviceNode, authority, baseUri, nodeRepo, edgeRepo);
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
  host: GraphNode,
  service: GraphNode,
  authority: string,
  baseUri: string,
  nodeRepo: NodeRepository,
  edgeRepo: EdgeRepository,
): void {
  // Find endpoints: edges from service where kind='SERVICE_ENDPOINT' -> target nodes
  const endpointEdges = edgeRepo.findBySource(service.id, 'SERVICE_ENDPOINT');

  // No endpoints -> suggest directory/file discovery
  if (endpointEdges.length === 0) {
    actions.push({
      kind: 'ffuf_discovery',
      description: `Discover endpoints on ${baseUri}`,
      command: `ffuf -u ${baseUri}/FUZZ -w /usr/share/wordlists/dirb/common.txt`,
      params: { hostId: host.id, serviceId: service.id },
    });
  }

  // Check vulnerabilities at service level (used for value_fuzz decision)
  // Filter out false_positive vulnerabilities — they should not prevent
  // the proposer from suggesting further testing actions.
  const vulnEdges = edgeRepo.findBySource(service.id, 'SERVICE_VULNERABILITY');
  const activeVulns = vulnEdges.filter((ve) => {
    const vulnNode = nodeRepo.findById(ve.targetId);
    if (vulnNode === undefined) {
      return false;
    }
    const vulnProps = parseProps(vulnNode);
    return vulnProps.status !== 'false_positive';
  });

  // For each endpoint: check inputs via ENDPOINT_INPUT edges (per-endpoint)
  for (const endpointEdge of endpointEdges) {
    const endpointNode = nodeRepo.findById(endpointEdge.targetId);
    if (endpointNode === undefined) {
      continue;
    }

    const endpointProps = parseProps(endpointNode);
    const endpointPath = endpointProps.path as string;

    // Find endpoint_input edges: edges from endpoint where kind='ENDPOINT_INPUT' -> input nodes
    const inputEdges = edgeRepo.findBySource(endpointNode.id, 'ENDPOINT_INPUT');

    if (inputEdges.length === 0) {
      actions.push({
        kind: 'parameter_discovery',
        description: `Discover input parameters for ${baseUri}${endpointPath}`,
        params: { hostId: host.id, serviceId: service.id, endpointId: endpointNode.id },
      });
    }

    // For each linked input: check observations
    for (const inputEdge of inputEdges) {
      const inputNode = nodeRepo.findById(inputEdge.targetId);
      if (inputNode === undefined) {
        continue;
      }

      const inputProps = parseProps(inputNode);
      const inputName = inputProps.name as string;
      const inputLocation = inputProps.location as string;

      // Find observations: edges from input where kind='INPUT_OBSERVATION' -> target nodes
      const observationEdges = edgeRepo.findBySource(inputNode.id, 'INPUT_OBSERVATION');

      if (observationEdges.length === 0) {
        actions.push({
          kind: 'value_collection',
          description: `Collect observed values for input "${inputName}" (${inputLocation})`,
          params: {
            hostId: host.id,
            serviceId: service.id,
            endpointId: endpointNode.id,
            inputId: inputNode.id,
          },
        });
      } else if (activeVulns.length === 0) {
        // Has input + observations, but no active vulnerabilities -> suggest fuzzing
        actions.push({
          kind: 'value_fuzz',
          description: `Fuzz input "${inputName}" (${inputLocation}) on ${baseUri}${endpointPath}`,
          params: {
            hostId: host.id,
            serviceId: service.id,
            endpointId: endpointNode.id,
            inputId: inputNode.id,
          },
        });
      }
    }
  }

  // Check vhosts: edges from host where kind='HOST_VHOST'
  const vhostEdges = edgeRepo.findBySource(host.id, 'HOST_VHOST');
  if (vhostEdges.length === 0) {
    actions.push({
      kind: 'vhost_discovery',
      description: `Discover virtual hosts for ${authority}`,
      params: { hostId: host.id, serviceId: service.id },
    });
  }

  // Check vulnerabilities -> suggest nuclei scan if no active vulnerabilities
  if (activeVulns.length === 0) {
    actions.push({
      kind: 'nuclei_scan',
      description: `Scan ${baseUri} for known vulnerabilities`,
      command: `nuclei -u ${baseUri} -jsonl`,
      params: { hostId: host.id, serviceId: service.id },
    });
  }
}
