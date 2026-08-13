import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { WorkerLifecycleRepository } from '../../db/repository/worker-lifecycle-repository.js';
import { ActionQueueRepository } from '../../db/repository/action-queue-repository.js';

export function registerWorkerTool(server: McpServer, db: Database.Database): void {
  const lifecycle = new WorkerLifecycleRepository(db);
  const actions = new ActionQueueRepository(db);
  server.tool(
    'worker',
    'Record Worker execution and artifacts for a leased Action',
    {
      action: z.enum([
        'start_execution',
        'register_artifact',
        'propose_child_action',
        'finish_execution',
        'renew_lease',
      ]),
      actionId: z.string().optional(),
      executionId: z.string().optional(),
      leaseOwner: z.string(),
      executor: z.string().optional(),
      command: z.string().optional(),
      inputJson: z.string().optional(),
      outputJson: z.string().optional(),
      outcome: z.enum(['succeeded', 'failed']).optional(),
      exitCode: z.number().int().optional(),
      errorType: z.string().optional(),
      errorMessage: z.string().optional(),
      stdoutArtifactId: z.string().optional(),
      stderrArtifactId: z.string().optional(),
      kind: z.string().optional(),
      path: z.string().optional(),
      sha256: z.string().optional(),
      mediaType: z.string().optional(),
      sensitivity: z.string().optional(),
      attrsJson: z.string().optional(),
      contentBase64: z.string().optional(),
      dedupeKey: z.string().optional(),
      paramsJson: z.string().optional(),
      priority: z.number().int().optional(),
      maxAttempts: z.number().int().positive().optional(),
    },
    async (input) => {
      try {
        if (input.action === 'renew_lease') {
          if (!input.actionId) throw new Error('actionId is required for renew_lease');
          const renewed = actions.renewLease(input.actionId, input.leaseOwner);
          if (!renewed) throw new Error('Action lease could not be renewed');
          return { content: [{ type: 'text', text: JSON.stringify(renewed, null, 2) }] };
        }
        if (input.action === 'start_execution') {
          if (!input.actionId || !input.executor) {
            throw new Error('actionId and executor are required for start_execution');
          }
          const execution = lifecycle.startExecution({
            actionId: input.actionId,
            leaseOwner: input.leaseOwner,
            executor: input.executor,
            command: input.command,
            inputJson: input.inputJson,
          });
          return { content: [{ type: 'text', text: JSON.stringify(execution, null, 2) }] };
        }
        if (!input.executionId) throw new Error('executionId is required');
        if (input.action === 'propose_child_action') {
          if (!input.kind || !input.dedupeKey) {
            throw new Error('kind and dedupeKey are required for propose_child_action');
          }
          const child = lifecycle.proposeChildAction({
            executionId: input.executionId,
            leaseOwner: input.leaseOwner,
            kind: input.kind,
            dedupeKey: input.dedupeKey,
            paramsJson: input.paramsJson,
            priority: input.priority,
            maxAttempts: input.maxAttempts,
          });
          return { content: [{ type: 'text', text: JSON.stringify(child, null, 2) }] };
        }
        if (input.action === 'register_artifact') {
          if (!input.kind || !input.path) {
            throw new Error('kind and path are required for register_artifact');
          }
          const artifact = lifecycle.registerArtifact({
            executionId: input.executionId,
            leaseOwner: input.leaseOwner,
            kind: input.kind,
            path: input.path,
            sha256: input.sha256,
            mediaType: input.mediaType,
            sensitivity: input.sensitivity,
            attrsJson: input.attrsJson,
            contentBase64: input.contentBase64,
          });
          return { content: [{ type: 'text', text: JSON.stringify(artifact, null, 2) }] };
        }
        if (!input.outcome) throw new Error('outcome is required for finish_execution');
        const result = lifecycle.finishExecution({
          executionId: input.executionId,
          leaseOwner: input.leaseOwner,
          outcome: input.outcome,
          outputJson: input.outputJson,
          exitCode: input.exitCode,
          errorType: input.errorType,
          errorMessage: input.errorMessage,
          stdoutArtifactId: input.stdoutArtifactId,
          stderrArtifactId: input.stderrArtifactId,
        });
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      } catch (error) {
        return {
          content: [{ type: 'text', text: error instanceof Error ? error.message : String(error) }],
          isError: true,
        };
      }
    },
  );
}
