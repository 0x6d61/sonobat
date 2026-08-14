import Database from 'better-sqlite3';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, describe, expect, it } from 'vitest';
import { migrateDatabase } from '../../src/db/migrate.js';
import { createMcpServer } from '../../src/mcp/server.js';
import type { McpProfile } from '../../src/types/domain.js';

const clients: Client[] = [];

async function toolNames(profile: McpProfile): Promise<string[]> {
  const db = new Database(':memory:');
  migrateDatabase(db);
  const server = createMcpServer(db, 'test', profile);
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

describe('MCP profiles', () => {
  it('exposes tactical planning tools without the Worker lease tool', async () => {
    const names = await toolNames('tactical');
    expect(names).toEqual([
      'actions',
      'engagements',
      'evaluations',
      'index_kb',
      'missions',
      'mutate',
      'query',
      'search_kb',
    ]);
  });

  it('exposes Worker operations without tactical planning tools', async () => {
    const names = await toolNames('worker');
    expect(names).toEqual(['evaluations', 'mutate', 'query', 'worker']);
    expect(names).not.toContain('missions');
    expect(names).not.toContain('actions');
  });
});
