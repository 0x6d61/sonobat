import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { createMcpServer } from '../../../src/mcp/server.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import { MissionRepository } from '../../../src/db/repository/mission-repository.js';
import { ActionQueueRepository } from '../../../src/db/repository/action-queue-repository.js';

describe('worker MCP tool', () => {
  let db: InstanceType<typeof Database>;
  let client: Client;
  let actionId: string;

  beforeEach(async () => {
    db = new Database(':memory:');
    migrateDatabase(db);
    const engagement = new EngagementRepository(db).create({ name: 'test' });
    const mission = new MissionRepository(db).create({
      engagementId: engagement.id,
      objective: '対象を調査する',
    });
    const actions = new ActionQueueRepository(db);
    actionId = actions.enqueue({
      engagementId: engagement.id,
      missionId: mission.id,
      kind: 'network_service_discovery',
      dedupeKey: 'test-action',
    }).id;
    actions.poll('worker-1');

    const server = createMcpServer(db);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    client = new Client({ name: 'test-client', version: '1.0.0' });
    await client.connect(clientTransport);
  });

  afterEach(async () => {
    await client.close();
  });

  it('Execution、Artifact、Action完了を記録する', async () => {
    const started = await client.callTool({
      name: 'worker',
      arguments: {
        action: 'start_execution',
        actionId,
        leaseOwner: 'worker-1',
        executor: 'worker-1',
      },
    });
    const execution = JSON.parse(
      (started.content as Array<{ type: string; text: string }>)[0].text,
    ) as { id: string };

    const registered = await client.callTool({
      name: 'worker',
      arguments: {
        action: 'register_artifact',
        executionId: execution.id,
        leaseOwner: 'worker-1',
        kind: 'stdout',
        path: 'artifact://stdout',
      },
    });
    expect(registered.isError).not.toBe(true);

    const finished = await client.callTool({
      name: 'worker',
      arguments: {
        action: 'finish_execution',
        executionId: execution.id,
        leaseOwner: 'worker-1',
        outcome: 'succeeded',
        exitCode: 0,
      },
    });
    const result = JSON.parse(
      (finished.content as Array<{ type: string; text: string }>)[0].text,
    ) as { action: { state: string } };
    expect(result.action.state).toBe('succeeded');
  });
});
