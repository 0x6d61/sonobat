import type Database from 'better-sqlite3';
import { ActionExecutionRepository } from './action-execution-repository.js';
import { ActionQueueRepository } from './action-queue-repository.js';
import { ArtifactRepository } from './artifact-repository.js';
import type {
  ActionExecution,
  ActionQueueItem,
  Artifact,
  RegisterArtifactInput,
} from '../../types/operational.js';

export interface StartExecutionInput {
  actionId: string;
  leaseOwner: string;
  executor: string;
  command?: string;
  inputJson?: string;
}

export interface FinishExecutionInput {
  executionId: string;
  leaseOwner: string;
  outcome: 'succeeded' | 'failed';
  outputJson?: string;
  exitCode?: number;
  errorType?: string;
  errorMessage?: string;
  stdoutArtifactId?: string;
  stderrArtifactId?: string;
}

export class WorkerLifecycleRepository {
  private readonly executions: ActionExecutionRepository;
  private readonly actions: ActionQueueRepository;
  private readonly artifacts: ArtifactRepository;
  private readonly finishTx: (input: FinishExecutionInput) => {
    execution: ActionExecution;
    action: ActionQueueItem;
  };

  constructor(private readonly db: Database.Database) {
    this.executions = new ActionExecutionRepository(db);
    this.actions = new ActionQueueRepository(db);
    this.artifacts = new ArtifactRepository(db);
    this.finishTx = this.db.transaction((input: FinishExecutionInput) => {
      const execution = this.requireActiveExecution(input.executionId, input.leaseOwner);
      if (input.outputJson !== undefined) JSON.parse(input.outputJson);
      this.requireExecutionArtifact(input.stdoutArtifactId, execution.id);
      this.requireExecutionArtifact(input.stderrArtifactId, execution.id);
      const completed = this.executions.complete(execution.id, {
        outputJson: input.outputJson,
        exitCode: input.exitCode,
        errorType: input.errorType,
        errorMessage: input.errorMessage,
        stdoutArtifactId: input.stdoutArtifactId,
        stderrArtifactId: input.stderrArtifactId,
      });
      if (completed === undefined) throw new Error(`Execution not found: ${execution.id}`);

      const actionUpdated =
        input.outcome === 'succeeded'
          ? this.actions.complete(execution.actionId)
          : this.actions.fail(
              execution.actionId,
              input.errorMessage ?? input.errorType ?? 'execution failed',
            );
      if (!actionUpdated) throw new Error(`Action could not be finished: ${execution.actionId}`);
      return { execution: completed, action: this.actions.findById(execution.actionId)! };
    });
  }

  startExecution(input: StartExecutionInput): ActionExecution {
    const action = this.requireLeasedAction(input.actionId, input.leaseOwner);
    if (input.inputJson !== undefined) JSON.parse(input.inputJson);
    const active = this.executions
      .findByAction(action.id)
      .find((execution) => execution.finishedAt === undefined);
    if (active !== undefined)
      throw new Error(`Action already has an active execution: ${active.id}`);
    return this.executions.create({
      actionId: action.id,
      runId: action.runId,
      executor: input.executor,
      command: input.command,
      inputJson: input.inputJson,
    });
  }

  registerArtifact(input: RegisterArtifactInput): Artifact {
    const execution = this.requireActiveExecution(input.executionId, input.leaseOwner);
    const action = this.actions.findById(execution.actionId)!;
    return this.artifacts.create({
      engagementId: action.engagementId,
      runId: action.runId,
      missionId: action.missionId,
      actionId: action.id,
      actionExecutionId: execution.id,
      producer: input.leaseOwner,
      kind: input.kind,
      path: input.path,
      sha256: input.sha256,
      mediaType: input.mediaType,
      sensitivity: input.sensitivity,
      attrsJson: input.attrsJson,
    });
  }

  finishExecution(input: FinishExecutionInput): {
    execution: ActionExecution;
    action: ActionQueueItem;
  } {
    return this.finishTx(input);
  }

  private requireActiveExecution(executionId: string, leaseOwner: string): ActionExecution {
    const execution = this.executions.findById(executionId);
    if (execution === undefined) throw new Error(`Execution not found: ${executionId}`);
    if (execution.finishedAt !== undefined)
      throw new Error(`Execution already finished: ${executionId}`);
    this.requireLeasedAction(execution.actionId, leaseOwner);
    return execution;
  }

  private requireLeasedAction(actionId: string, leaseOwner: string): ActionQueueItem {
    const action = this.actions.findById(actionId);
    if (action === undefined) throw new Error(`Action not found: ${actionId}`);
    if (action.state !== 'running') throw new Error(`Action is not running: ${actionId}`);
    if (action.leaseOwner !== leaseOwner) throw new Error(`Action lease owner does not match`);
    if (
      action.leaseExpiresAt === undefined ||
      new Date(action.leaseExpiresAt).getTime() <= Date.now()
    ) {
      throw new Error(`Action lease has expired`);
    }
    return action;
  }

  private requireExecutionArtifact(artifactId: string | undefined, executionId: string): void {
    if (artifactId === undefined) return;
    const row = this.db
      .prepare('SELECT action_execution_id FROM artifacts WHERE id = ?')
      .get(artifactId) as { action_execution_id: string | null } | undefined;
    if (row?.action_execution_id !== executionId) {
      throw new Error(`Artifact does not belong to execution: ${artifactId}`);
    }
  }
}
