import Database from 'better-sqlite3';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, describe, expect, it } from 'vitest';
import { migrateDatabase } from '../../src/db/migrate.js';
import { createMcpServer } from '../../src/mcp/server.js';

const clients: Client[] = [];

async function toolNames(): Promise<string[]> {
  const db = new Database(':memory:');
  migrateDatabase(db);
  const server = createMcpServer(db, 'test');
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test', version: '1' });
  clients.push(client);
  await client.connect(clientTransport);
  return (await client.listTools()).tools.map((tool) => tool.name).sort();
}

afterEach(async () => {
  await Promise.all(clients.splice(0).map((client) => client.close()));
});

describe('MCP core model', () => {
  it('exposes only Assessment, Entity, Relation, Activity, and Artifact operations', async () => {
    expect(await toolNames()).toEqual([
      'activities',
      'artifacts',
      'assessments',
      'mutate',
      'query',
    ]);
  });
});
