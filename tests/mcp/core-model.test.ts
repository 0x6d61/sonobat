import Database from 'better-sqlite3';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, describe, expect, it } from 'vitest';
import { migrateDatabase } from '../../src/db/migrate.js';
import { createMcpServer } from '../../src/mcp/server.js';

const clients: Client[] = [];

function textContent(result: unknown): string {
  const content = (result as { content?: unknown }).content as Array<{ text?: unknown }>;
  return String(content[0]?.text);
}

afterEach(async () => {
  await Promise.all(clients.splice(0).map((client) => client.close()));
});

describe('core MCP tools', () => {
  it('creates Assessments and keeps graph writes isolated', async () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const server = createMcpServer(db, 'test');
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: 'test', version: '1' });
    clients.push(client);
    await client.connect(clientTransport);

    const first = await client.callTool({
      name: 'assessments',
      arguments: { action: 'create', name: 'first' },
    });
    const second = await client.callTool({
      name: 'assessments',
      arguments: { action: 'create', name: 'second' },
    });
    const firstId = (JSON.parse(textContent(first)) as { id: string }).id;
    const secondId = (JSON.parse(textContent(second)) as { id: string }).id;

    const entity = await client.callTool({
      name: 'mutate',
      arguments: {
        action: 'upsert_entity',
        assessmentId: firstId,
        kind: 'host',
        naturalKey: 'host:shared',
      },
    });
    const entityId = (JSON.parse(textContent(entity)) as { entity: { id: string } }).entity.id;
    const hidden = await client.callTool({
      name: 'query',
      arguments: { action: 'get_entity', assessmentId: secondId, id: entityId },
    });
    expect(hidden.isError).toBe(true);

    const context = await client.callTool({
      name: 'assessments',
      arguments: { action: 'get_context', assessmentId: firstId },
    });
    expect(JSON.parse(textContent(context))).toEqual(
      expect.objectContaining({
        assessment: expect.objectContaining({ id: firstId }),
        entities: [expect.objectContaining({ id: entityId, assessmentId: firstId })],
        relations: [],
        activities: [],
        artifacts: [],
      }),
    );
    db.close();
  });
});
