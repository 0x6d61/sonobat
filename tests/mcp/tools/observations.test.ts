import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { randomUUID } from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { createMcpServer } from '../../../src/mcp/server.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';

describe('observe MCP tool', () => {
  let db: InstanceType<typeof Database>;
  let client: Client;
  let artifactId: string;

  beforeEach(async () => {
    db = new Database(':memory:');
    migrateDatabase(db);
    const engagementId = new EngagementRepository(db).create({ name: 'test' }).id;
    artifactId = randomUUID();
    db.prepare(
      `INSERT INTO artifacts (id, tool, kind, path, captured_at, engagement_id)
       VALUES (?, 'worker', 'tool_output', '/tmp/result', ?, ?)`,
    ).run(artifactId, new Date().toISOString(), engagementId);

    const server = createMcpServer(db);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    client = new Client({ name: 'test-client', version: '1.0.0' });
    await client.connect(clientTransport);
  });

  afterEach(async () => {
    await client.close();
    db.close();
  });

  it('Observation、Node、Findingを原子的に登録する', async () => {
    const response = await client.callTool({
      name: 'observe',
      arguments: {
        artifactId,
        actor: 'worker-1',
        contentJson: JSON.stringify({ summary: 'finding discovered' }),
        nodesJson: JSON.stringify([
          {
            ref: 'host',
            kind: 'host',
            props: { authorityKind: 'IP', authority: '192.0.2.10' },
          },
        ]),
        findingsJson: JSON.stringify([
          {
            canonicalKey: 'host-finding:192.0.2.10',
            title: 'Host finding',
            severity: 'high',
            confidence: 'high',
            nodeRef: 'host',
          },
        ]),
      },
    });

    expect(response.isError).not.toBe(true);
    const result = JSON.parse(
      (response.content as Array<{ type: string; text: string }>)[0].text,
    ) as { findingIds: string[] };
    expect(result.findingIds).toHaveLength(1);
    expect(db.prepare('SELECT COUNT(*) count FROM findings').get()).toEqual({ count: 1 });
    expect(db.prepare('SELECT COUNT(*) count FROM observation_findings').get()).toEqual({
      count: 1,
    });
  });
});
