import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { WorkerLifecycleRepository } from '../../db/repository/worker-lifecycle-repository.js';

export function registerWorkerTool(server: McpServer, db: Database.Database): void {
  const lifecycle = new WorkerLifecycleRepository(db);
  server.tool(
    'worker',
    'Record Worker execution and artifacts for a leased Action',
    {
      action: z.enum(['start_execution', 'register_artifact', 'finish_execution']),
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
    },
    async (input) => {
      try {
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
