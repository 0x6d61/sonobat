import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
  let artifactRoot: string;
  let previousArtifactRoot: string | undefined;

  beforeEach(async () => {
    db = new Database(':memory:');
    artifactRoot = mkdtempSync(join(tmpdir(), 'sonobat-mcp-worker-test-'));
    previousArtifactRoot = process.env.SONOBAT_ARTIFACT_DIR;
    process.env.SONOBAT_ARTIFACT_DIR = artifactRoot;
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
    db.close();
    rmSync(artifactRoot, { recursive: true, force: true });
    if (previousArtifactRoot === undefined) delete process.env.SONOBAT_ARTIFACT_DIR;
    else process.env.SONOBAT_ARTIFACT_DIR = previousArtifactRoot;
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
        path: 'stdout.txt',
        contentBase64: Buffer.from('command output').toString('base64'),
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

  it('子Actionを実行待ちへ入れずに提案する', async () => {
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

    const proposed = await client.callTool({
      name: 'worker',
      arguments: {
        action: 'propose_child_action',
        executionId: execution.id,
        leaseOwner: 'worker-1',
        kind: 'http_service_review',
        dedupeKey: 'child:mcp-proposal',
      },
    });
    expect(proposed.isError).not.toBe(true);
    const child = JSON.parse(
      (proposed.content as Array<{ type: string; text: string }>)[0].text,
    ) as { state: string; parentActionId: string };
    expect(child.state).toBe('proposed');
    expect(child.parentActionId).toBe(actionId);
  });
});
