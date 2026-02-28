/**
 * sonobat — MCP Mutation Tools
 *
 * Tools for manually adding data to the AttackDataGraph.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { HostRepository } from '../../db/repository/host-repository.js';
import { ArtifactRepository } from '../../db/repository/artifact-repository.js';
import { CredentialRepository } from '../../db/repository/credential-repository.js';
import { VulnerabilityRepository } from '../../db/repository/vulnerability-repository.js';
import { CveRepository } from '../../db/repository/cve-repository.js';

/**
 * Get or create a singleton "manual" artifact for manual data entry.
 * Reused across all manual mutations to avoid artifact proliferation.
 */
function getOrCreateManualArtifact(db: Database.Database): string {
  const artifactRepo = new ArtifactRepository(db);
  const existing = artifactRepo.findByTool('manual');
  if (existing.length > 0) {
    return existing[0].id;
  }
  const artifact = artifactRepo.create({
    tool: 'manual',
    kind: 'manual_entry',
    path: 'manual',
    capturedAt: new Date().toISOString(),
  });
  return artifact.id;
}

export function registerMutationTools(server: McpServer, db: Database.Database): void {
  // 1. add_host
  server.tool(
    'add_host',
    'Manually add a host to the AttackDataGraph',
    {
      authority: z.string().describe('IP address or domain name'),
      authorityKind: z.enum(['IP', 'DOMAIN']).describe('Type of authority'),
    },
    async ({ authority, authorityKind }) => {
      const hostRepo = new HostRepository(db);
      const existing = hostRepo.findByAuthority(authority);
      if (existing) {
        return {
          content: [
            { type: 'text', text: `Host already exists: ${JSON.stringify(existing, null, 2)}` },
          ],
        };
      }
      const host = hostRepo.create({
        authorityKind,
        authority,
        resolvedIpsJson: '[]',
      });
      return { content: [{ type: 'text', text: JSON.stringify(host, null, 2) }] };
    },
  );

  // 2. add_credential
  server.tool(
    'add_credential',
    'Manually add a credential for a service',
    {
      serviceId: z.string().describe('Service UUID'),
      username: z.string().describe('Username'),
      secret: z.string().describe('Secret value (password, token, etc.)'),
      secretType: z.enum(['password', 'token', 'api_key', 'ssh_key']).describe('Type of secret'),
      source: z
        .enum(['brute_force', 'default', 'leaked', 'manual'])
        .describe('How the credential was obtained'),
      confidence: z.enum(['high', 'medium', 'low']).describe('Confidence level').default('medium'),
    },
    async ({ serviceId, username, secret, secretType, source, confidence }) => {
      const artifactId = getOrCreateManualArtifact(db);
      const credentialRepo = new CredentialRepository(db);
      const credential = credentialRepo.create({
        serviceId,
        username,
        secret,
        secretType,
        source,
        confidence,
        evidenceArtifactId: artifactId,
      });
      return { content: [{ type: 'text', text: JSON.stringify(credential, null, 2) }] };
    },
  );

  // 3. add_vulnerability
  server.tool(
    'add_vulnerability',
    'Manually add a vulnerability for a service',
    {
      serviceId: z.string().describe('Service UUID'),
      vulnType: z.string().describe('Vulnerability type (sqli, xss, rce, lfi, ssrf, etc.)'),
      title: z.string().describe('Vulnerability title'),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).describe('Severity level'),
      confidence: z.enum(['high', 'medium', 'low']).describe('Confidence level').default('medium'),
      endpointId: z.string().optional().describe('HTTP endpoint UUID (optional)'),
      description: z.string().optional().describe('Detailed description (optional)'),
    },
    async ({ serviceId, vulnType, title, severity, confidence, endpointId, description }) => {
      const artifactId = getOrCreateManualArtifact(db);
      const vulnRepo = new VulnerabilityRepository(db);
      const vuln = vulnRepo.create({
        serviceId,
        endpointId,
        vulnType,
        title,
        description,
        severity,
        confidence,
        evidenceArtifactId: artifactId,
      });
      return { content: [{ type: 'text', text: JSON.stringify(vuln, null, 2) }] };
    },
  );

  // 4. update_vulnerability_status
  server.tool(
    'update_vulnerability_status',
    'Update the status of a vulnerability (e.g. mark as confirmed or false positive)',
    {
      id: z.string().describe('Vulnerability UUID'),
      status: z
        .enum(['unverified', 'confirmed', 'false_positive', 'not_exploitable'])
        .describe('New status for the vulnerability'),
    },
    async ({ id, status }) => {
      const vulnRepo = new VulnerabilityRepository(db);
      const updated = vulnRepo.updateStatus(id, status);
      if (!updated) {
        return {
          content: [{ type: 'text', text: `Vulnerability not found: ${id}` }],
          isError: true,
        };
      }
      const vuln = vulnRepo.findById(id);
      return { content: [{ type: 'text', text: JSON.stringify(vuln, null, 2) }] };
    },
  );

  // 5. link_cve
  server.tool(
    'link_cve',
    'Link a CVE record to an existing vulnerability',
    {
      vulnerabilityId: z.string().describe('Vulnerability UUID'),
      cveId: z.string().describe('CVE identifier (e.g. CVE-2021-44228)'),
      description: z.string().optional().describe('CVE description'),
      cvssScore: z.number().optional().describe('CVSS score (0.0 - 10.0)'),
      cvssVector: z.string().optional().describe('CVSS vector string'),
      referenceUrl: z.string().optional().describe('Reference URL'),
    },
    async ({ vulnerabilityId, cveId, description, cvssScore, cvssVector, referenceUrl }) => {
      const cveRepo = new CveRepository(db);
      const cve = cveRepo.create({
        vulnerabilityId,
        cveId,
        description,
        cvssScore,
        cvssVector,
        referenceUrl,
      });
      return { content: [{ type: 'text', text: JSON.stringify(cve, null, 2) }] };
    },
  );
}
