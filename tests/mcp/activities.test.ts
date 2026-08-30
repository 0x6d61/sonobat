import Database from 'better-sqlite3';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, describe, expect, it } from 'vitest';
import { migrateDatabase } from '../../src/db/migrate.js';
import { createMcpServer } from '../../src/mcp/server.js';
import { AssessmentRepository } from '../../src/db/repository/assessment-repository.js';

const clients: Client[] = [];

function textContent(result: unknown): string {
  const content = (result as { content?: unknown }).content as Array<{ text?: unknown }>;
  return String(content[0]?.text);
}

afterEach(async () => {
  await Promise.all(clients.splice(0).map((client) => client.close()));
});

describe('activities MCP tool', () => {
  it('records and queries an Activity by Assessment', async () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const assessment = new AssessmentRepository(db).create({ name: 'htb-box' });
    const server = createMcpServer(db, 'test');
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: 'test', version: '1' });
    clients.push(client);
    await client.connect(clientTransport);

    const recorded = await client.callTool({
      name: 'activities',
      arguments: {
        action: 'record',
        assessmentId: assessment.id,
        kind: 'nmap',
        description: 'nmap -sV target',
        status: 'completed',
        resultSummary: '22/tcp open',
      },
    });
    expect(recorded.isError).not.toBe(true);
    const activity = JSON.parse(textContent(recorded)) as { id: string };

    const listed = await client.callTool({
      name: 'activities',
      arguments: { action: 'list', assessmentId: assessment.id },
    });
    expect(JSON.parse(textContent(listed))).toEqual([
      expect.objectContaining({ id: activity.id, kind: 'nmap', status: 'completed' }),
    ]);

    const fetched = await client.callTool({
      name: 'activities',
      arguments: { action: 'get', assessmentId: assessment.id, id: activity.id },
    });
    expect(JSON.parse(textContent(fetched))).toEqual(
      expect.objectContaining({ id: activity.id, resultSummary: '22/tcp open' }),
    );
    db.close();
  });

  it('does not expose an Activity from another Assessment', async () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const assessments = new AssessmentRepository(db);
    const first = assessments.create({ name: 'first' });
    const second = assessments.create({ name: 'second' });
    const server = createMcpServer(db, 'test');
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: 'test', version: '1' });
    clients.push(client);
    await client.connect(clientTransport);

    const recorded = await client.callTool({
      name: 'activities',
      arguments: {
        action: 'record',
        assessmentId: first.id,
        kind: 'curl',
        description: 'GET /',
        status: 'completed',
      },
    });
    const activity = JSON.parse(textContent(recorded)) as { id: string };
    const fetched = await client.callTool({
      name: 'activities',
      arguments: { action: 'get', assessmentId: second.id, id: activity.id },
    });
    expect(fetched.isError).toBe(true);
    db.close();
  });
});
