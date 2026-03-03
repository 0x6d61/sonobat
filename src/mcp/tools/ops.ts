/**
 * sonobat — MCP Ops Tool (unified)
 *
 * Single 'ops' tool with an 'action' parameter for managing
 * engagements, runs, action queue, and action executions.
 *
 * Actions: create_engagement, list_engagements, get_engagement,
 *   update_engagement, delete_engagement, create_run, list_runs,
 *   get_run, update_run_status, enqueue_action, poll_action,
 *   complete_action, fail_action, cancel_action, list_actions,
 *   get_execution, list_executions
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { EngagementRepository } from '../../db/repository/engagement-repository.js';
import { RunRepository } from '../../db/repository/run-repository.js';
import { ActionQueueRepository } from '../../db/repository/action-queue-repository.js';
import { ActionExecutionRepository } from '../../db/repository/action-execution-repository.js';

export function registerOpsTools(server: McpServer, db: Database.Database): void {
  const engagementRepo = new EngagementRepository(db);
  const runRepo = new RunRepository(db);
  const actionQueueRepo = new ActionQueueRepository(db);
  const actionExecRepo = new ActionExecutionRepository(db);

  server.tool(
    'ops',
    'Manage operational entities. Actions: create_engagement, list_engagements, get_engagement, update_engagement, delete_engagement, create_run, list_runs, get_run, update_run_status, enqueue_action, poll_action, complete_action, fail_action, cancel_action, list_actions, get_execution, list_executions',
    {
      action: z.enum([
        'create_engagement',
        'list_engagements',
        'get_engagement',
        'update_engagement',
        'delete_engagement',
        'create_run',
        'list_runs',
        'get_run',
        'update_run_status',
        'enqueue_action',
        'poll_action',
        'complete_action',
        'fail_action',
        'cancel_action',
        'list_actions',
        'get_execution',
        'list_executions',
      ]),
      id: z.string().optional().describe('Entity ID'),
      engagementId: z.string().optional().describe('Engagement ID'),
      runId: z.string().optional().describe('Run ID'),
      actionId: z.string().optional().describe('Action queue item ID'),
      name: z.string().optional().describe('Engagement name'),
      environment: z.string().optional().describe('Environment (e.g. stg, prod)'),
      status: z.string().optional().describe('Status value'),
      triggerKind: z.string().optional().describe('Run trigger kind'),
      triggerRef: z.string().optional().describe('Run trigger reference'),
      kind: z.string().optional().describe('Action kind'),
      dedupeKey: z.string().optional().describe('Action deduplication key'),
      leaseOwner: z.string().optional().describe('Lease owner for poll'),
      executor: z.string().optional().describe('Executor name'),
      errorMessage: z.string().optional().describe('Error message for fail'),
      scopeJson: z.string().optional().describe('Scope as JSON'),
      policyJson: z.string().optional().describe('Policy as JSON'),
      scheduleCron: z.string().optional().describe('Schedule cron expression'),
      paramsJson: z.string().optional().describe('Action parameters as JSON'),
      summaryJson: z.string().optional().describe('Run summary as JSON'),
      inputJson: z.string().optional().describe('Execution input as JSON'),
      priority: z.number().optional().describe('Action priority (lower = higher)'),
      maxAttempts: z.number().optional().describe('Max retry attempts'),
      leaseDurationSec: z.number().optional().describe('Lease duration in seconds'),
      limit: z.number().optional().describe('Result limit'),
      state: z.string().optional().describe('Action state filter'),
      parentActionId: z.string().optional().describe('Parent action ID'),
      availableAt: z.string().optional().describe('Available at timestamp'),
    },
    async ({
      action,
      id,
      engagementId,
      runId,
      actionId,
      name,
      environment,
      status,
      triggerKind,
      triggerRef,
      kind,
      dedupeKey,
      leaseOwner,
      errorMessage,
      scopeJson,
      policyJson,
      scheduleCron,
      paramsJson,
      summaryJson,
      priority,
      maxAttempts,
      leaseDurationSec,
      limit,
      state,
      parentActionId,
      availableAt,
    }) => {
      switch (action) {
        // ----------------------------------------------------------------
        // Engagement actions
        // ----------------------------------------------------------------
        case 'create_engagement': {
          if (!name) {
            return {
              content: [
                { type: 'text', text: 'name parameter is required for create_engagement' },
              ],
              isError: true,
            };
          }
          const engagement = engagementRepo.create({
            name,
            environment,
            scopeJson,
            policyJson,
            scheduleCron,
            status,
          });
          return { content: [{ type: 'text', text: JSON.stringify(engagement, null, 2) }] };
        }

        case 'list_engagements': {
          const engagements = status
            ? engagementRepo.findByStatus(status)
            : engagementRepo.list();
          return { content: [{ type: 'text', text: JSON.stringify(engagements, null, 2) }] };
        }

        case 'get_engagement': {
          if (!id) {
            return {
              content: [
                { type: 'text', text: 'id parameter is required for get_engagement' },
              ],
              isError: true,
            };
          }
          const engagement = engagementRepo.findById(id);
          if (!engagement) {
            return {
              content: [{ type: 'text', text: `Engagement not found: ${id}` }],
              isError: true,
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(engagement, null, 2) }] };
        }

        case 'update_engagement': {
          if (!id) {
            return {
              content: [
                { type: 'text', text: 'id parameter is required for update_engagement' },
              ],
              isError: true,
            };
          }
          const fields: Record<string, unknown> = {};
          if (name !== undefined) fields.name = name;
          if (environment !== undefined) fields.environment = environment;
          if (scopeJson !== undefined) fields.scopeJson = scopeJson;
          if (policyJson !== undefined) fields.policyJson = policyJson;
          if (scheduleCron !== undefined) fields.scheduleCron = scheduleCron;
          if (status !== undefined) fields.status = status;

          const updated = engagementRepo.update(id, fields);
          if (!updated) {
            return {
              content: [{ type: 'text', text: `Engagement not found: ${id}` }],
              isError: true,
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(updated, null, 2) }] };
        }

        case 'delete_engagement': {
          if (!id) {
            return {
              content: [
                { type: 'text', text: 'id parameter is required for delete_engagement' },
              ],
              isError: true,
            };
          }
          const deleted = engagementRepo.delete(id);
          if (!deleted) {
            return {
              content: [{ type: 'text', text: `Engagement not found: ${id}` }],
              isError: true,
            };
          }
          return {
            content: [{ type: 'text', text: `Engagement ${id} deleted successfully.` }],
          };
        }

        // ----------------------------------------------------------------
        // Run actions
        // ----------------------------------------------------------------
        case 'create_run': {
          if (!engagementId) {
            return {
              content: [
                { type: 'text', text: 'engagementId parameter is required for create_run' },
              ],
              isError: true,
            };
          }
          if (!triggerKind) {
            return {
              content: [
                { type: 'text', text: 'triggerKind parameter is required for create_run' },
              ],
              isError: true,
            };
          }
          if (!status) {
            return {
              content: [
                { type: 'text', text: 'status parameter is required for create_run' },
              ],
              isError: true,
            };
          }
          const run = runRepo.create({
            engagementId,
            triggerKind,
            triggerRef,
            status,
          });
          return { content: [{ type: 'text', text: JSON.stringify(run, null, 2) }] };
        }

        case 'list_runs': {
          if (!engagementId) {
            return {
              content: [
                { type: 'text', text: 'engagementId parameter is required for list_runs' },
              ],
              isError: true,
            };
          }
          const runs = runRepo.findByEngagement(engagementId, limit);
          return { content: [{ type: 'text', text: JSON.stringify(runs, null, 2) }] };
        }

        case 'get_run': {
          if (!id) {
            return {
              content: [{ type: 'text', text: 'id parameter is required for get_run' }],
              isError: true,
            };
          }
          const run = runRepo.findById(id);
          if (!run) {
            return {
              content: [{ type: 'text', text: `Run not found: ${id}` }],
              isError: true,
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(run, null, 2) }] };
        }

        case 'update_run_status': {
          if (!id) {
            return {
              content: [
                { type: 'text', text: 'id parameter is required for update_run_status' },
              ],
              isError: true,
            };
          }
          if (!status) {
            return {
              content: [
                { type: 'text', text: 'status parameter is required for update_run_status' },
              ],
              isError: true,
            };
          }
          const updatedRun = runRepo.updateStatus(id, status, summaryJson);
          if (!updatedRun) {
            return {
              content: [{ type: 'text', text: `Run not found: ${id}` }],
              isError: true,
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(updatedRun, null, 2) }] };
        }

        // ----------------------------------------------------------------
        // ActionQueue actions
        // ----------------------------------------------------------------
        case 'enqueue_action': {
          if (!engagementId) {
            return {
              content: [
                {
                  type: 'text',
                  text: 'engagementId parameter is required for enqueue_action',
                },
              ],
              isError: true,
            };
          }
          if (!kind) {
            return {
              content: [
                { type: 'text', text: 'kind parameter is required for enqueue_action' },
              ],
              isError: true,
            };
          }
          if (!dedupeKey) {
            return {
              content: [
                { type: 'text', text: 'dedupeKey parameter is required for enqueue_action' },
              ],
              isError: true,
            };
          }
          const item = actionQueueRepo.enqueue({
            engagementId,
            runId,
            parentActionId,
            kind,
            priority,
            dedupeKey,
            paramsJson,
            state,
            maxAttempts,
            availableAt,
          });
          return { content: [{ type: 'text', text: JSON.stringify(item, null, 2) }] };
        }

        case 'poll_action': {
          if (!leaseOwner) {
            return {
              content: [
                { type: 'text', text: 'leaseOwner parameter is required for poll_action' },
              ],
              isError: true,
            };
          }
          const polled = actionQueueRepo.poll(leaseOwner, leaseDurationSec);
          if (!polled) {
            return {
              content: [{ type: 'text', text: 'No action available to poll' }],
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(polled, null, 2) }] };
        }

        case 'complete_action': {
          if (!id) {
            return {
              content: [
                { type: 'text', text: 'id parameter is required for complete_action' },
              ],
              isError: true,
            };
          }
          const completed = actionQueueRepo.complete(id);
          if (!completed) {
            return {
              content: [
                { type: 'text', text: `Action not found or not in running state: ${id}` },
              ],
              isError: true,
            };
          }
          return {
            content: [{ type: 'text', text: `Action ${id} completed successfully.` }],
          };
        }

        case 'fail_action': {
          if (!id) {
            return {
              content: [
                { type: 'text', text: 'id parameter is required for fail_action' },
              ],
              isError: true,
            };
          }
          if (!errorMessage) {
            return {
              content: [
                { type: 'text', text: 'errorMessage parameter is required for fail_action' },
              ],
              isError: true,
            };
          }
          const failed = actionQueueRepo.fail(id, errorMessage);
          if (!failed) {
            return {
              content: [
                { type: 'text', text: `Action not found or not in running state: ${id}` },
              ],
              isError: true,
            };
          }
          const afterFail = actionQueueRepo.findById(id);
          return {
            content: [{ type: 'text', text: JSON.stringify(afterFail, null, 2) }],
          };
        }

        case 'cancel_action': {
          if (!id) {
            return {
              content: [
                { type: 'text', text: 'id parameter is required for cancel_action' },
              ],
              isError: true,
            };
          }
          const cancelled = actionQueueRepo.cancel(id);
          if (!cancelled) {
            return {
              content: [{ type: 'text', text: `Action not found: ${id}` }],
              isError: true,
            };
          }
          return {
            content: [{ type: 'text', text: `Action ${id} cancelled successfully.` }],
          };
        }

        case 'list_actions': {
          if (!engagementId) {
            return {
              content: [
                { type: 'text', text: 'engagementId parameter is required for list_actions' },
              ],
              isError: true,
            };
          }
          const actions = actionQueueRepo.findByEngagement(engagementId, state);
          return { content: [{ type: 'text', text: JSON.stringify(actions, null, 2) }] };
        }

        // ----------------------------------------------------------------
        // ActionExecution actions
        // ----------------------------------------------------------------
        case 'get_execution': {
          if (!id) {
            return {
              content: [
                { type: 'text', text: 'id parameter is required for get_execution' },
              ],
              isError: true,
            };
          }
          const execution = actionExecRepo.findById(id);
          if (!execution) {
            return {
              content: [{ type: 'text', text: `Execution not found: ${id}` }],
              isError: true,
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(execution, null, 2) }] };
        }

        case 'list_executions': {
          if (actionId) {
            const executions = actionExecRepo.findByAction(actionId);
            return {
              content: [{ type: 'text', text: JSON.stringify(executions, null, 2) }],
            };
          }
          if (runId) {
            const executions = actionExecRepo.findByRun(runId);
            return {
              content: [{ type: 'text', text: JSON.stringify(executions, null, 2) }],
            };
          }
          return {
            content: [
              {
                type: 'text',
                text: 'actionId or runId parameter is required for list_executions',
              },
            ],
            isError: true,
          };
        }
      }
    },
  );
}
