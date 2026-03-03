/**
 * sonobat — MCP Findings Tool (unified)
 *
 * Single 'findings' tool with an 'action' parameter for managing
 * findings, finding events, and risk snapshots.
 *
 * Actions: upsert_finding, get_finding, list_findings,
 *   update_finding_state, list_finding_events,
 *   create_risk_snapshot, get_risk_snapshot,
 *   list_risk_snapshots, latest_risk_snapshot
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type Database from 'better-sqlite3';
import { z } from 'zod';
import { FindingRepository } from '../../db/repository/finding-repository.js';
import { RiskSnapshotRepository } from '../../db/repository/risk-snapshot-repository.js';

export function registerFindingsTools(server: McpServer, db: Database.Database): void {
  const findingRepo = new FindingRepository(db);
  const riskSnapshotRepo = new RiskSnapshotRepository(db);

  server.tool(
    'findings',
    'Manage findings and risk snapshots. Actions: upsert_finding, get_finding, list_findings, update_finding_state, list_finding_events, create_risk_snapshot, get_risk_snapshot, list_risk_snapshots, latest_risk_snapshot',
    {
      action: z.enum([
        'upsert_finding',
        'get_finding',
        'list_findings',
        'update_finding_state',
        'list_finding_events',
        'create_risk_snapshot',
        'get_risk_snapshot',
        'list_risk_snapshots',
        'latest_risk_snapshot',
      ]),
      id: z.string().optional().describe('Entity ID'),
      engagementId: z.string().optional().describe('Engagement ID'),
      canonicalKey: z.string().optional().describe('Finding canonical key'),
      nodeId: z.string().optional().describe('Associated node ID'),
      title: z.string().optional().describe('Finding title'),
      severity: z.string().optional().describe('Finding severity'),
      confidence: z.string().optional().describe('Finding confidence'),
      state: z.string().optional().describe('Finding state'),
      stateReason: z.string().optional().describe('Reason for state change'),
      runId: z.string().optional().describe('Run ID'),
      findingId: z.string().optional().describe('Finding ID for events'),
      attrsJson: z.string().optional().describe('Attributes as JSON'),
      score: z.number().optional().describe('Risk score'),
      openCritical: z.number().optional().describe('Open critical count'),
      openHigh: z.number().optional().describe('Open high count'),
      openMedium: z.number().optional().describe('Open medium count'),
      openLow: z.number().optional().describe('Open low count'),
      openInfo: z.number().optional().describe('Open info count'),
      openTotal: z.number().optional().describe('Open total count'),
      attackPathCount: z.number().optional().describe('Attack path count'),
      exposedCredCount: z.number().optional().describe('Exposed credential count'),
      modelVersion: z.string().optional().describe('Risk model version'),
      limit: z.number().optional().describe('Result limit'),
    },
    async ({
      action,
      id,
      engagementId,
      canonicalKey,
      nodeId,
      title,
      severity,
      confidence,
      state,
      stateReason,
      runId,
      findingId,
      attrsJson,
      score,
      openCritical,
      openHigh,
      openMedium,
      openLow,
      openInfo,
      openTotal,
      attackPathCount,
      exposedCredCount,
      modelVersion,
      limit,
    }) => {
      switch (action) {
        // ----------------------------------------------------------------
        // Finding actions
        // ----------------------------------------------------------------
        case 'upsert_finding': {
          if (!engagementId) {
            return {
              content: [
                {
                  type: 'text',
                  text: 'engagementId parameter is required for upsert_finding',
                },
              ],
              isError: true,
            };
          }
          if (!canonicalKey) {
            return {
              content: [
                {
                  type: 'text',
                  text: 'canonicalKey parameter is required for upsert_finding',
                },
              ],
              isError: true,
            };
          }
          if (!title) {
            return {
              content: [
                { type: 'text', text: 'title parameter is required for upsert_finding' },
              ],
              isError: true,
            };
          }
          if (!severity) {
            return {
              content: [
                { type: 'text', text: 'severity parameter is required for upsert_finding' },
              ],
              isError: true,
            };
          }
          if (!confidence) {
            return {
              content: [
                {
                  type: 'text',
                  text: 'confidence parameter is required for upsert_finding',
                },
              ],
              isError: true,
            };
          }
          const result = findingRepo.upsert({
            engagementId,
            canonicalKey,
            title,
            severity,
            confidence,
            nodeId,
            state,
            runId,
            attrsJson,
          });
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ ...result.finding, created: result.created }, null, 2),
              },
            ],
          };
        }

        case 'get_finding': {
          if (!id) {
            return {
              content: [
                { type: 'text', text: 'id parameter is required for get_finding' },
              ],
              isError: true,
            };
          }
          const finding = findingRepo.findById(id);
          if (!finding) {
            return {
              content: [{ type: 'text', text: `Finding not found: ${id}` }],
              isError: true,
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(finding, null, 2) }] };
        }

        case 'list_findings': {
          if (!engagementId) {
            return {
              content: [
                {
                  type: 'text',
                  text: 'engagementId parameter is required for list_findings',
                },
              ],
              isError: true,
            };
          }
          const opts: { state?: string; severity?: string } = {};
          if (state) opts.state = state;
          if (severity) opts.severity = severity;
          const findings = findingRepo.findByEngagement(engagementId, opts);
          return {
            content: [{ type: 'text', text: JSON.stringify(findings, null, 2) }],
          };
        }

        case 'update_finding_state': {
          if (!id) {
            return {
              content: [
                { type: 'text', text: 'id parameter is required for update_finding_state' },
              ],
              isError: true,
            };
          }
          if (!state) {
            return {
              content: [
                {
                  type: 'text',
                  text: 'state parameter is required for update_finding_state',
                },
              ],
              isError: true,
            };
          }
          const updated = findingRepo.updateState(id, state, stateReason);
          if (!updated) {
            return {
              content: [{ type: 'text', text: `Finding not found: ${id}` }],
              isError: true,
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(updated, null, 2) }] };
        }

        case 'list_finding_events': {
          if (!findingId) {
            return {
              content: [
                {
                  type: 'text',
                  text: 'findingId parameter is required for list_finding_events',
                },
              ],
              isError: true,
            };
          }
          const events = findingRepo.getEvents(findingId);
          return { content: [{ type: 'text', text: JSON.stringify(events, null, 2) }] };
        }

        // ----------------------------------------------------------------
        // RiskSnapshot actions
        // ----------------------------------------------------------------
        case 'create_risk_snapshot': {
          if (!engagementId) {
            return {
              content: [
                {
                  type: 'text',
                  text: 'engagementId parameter is required for create_risk_snapshot',
                },
              ],
              isError: true,
            };
          }
          if (score === undefined || score === null) {
            return {
              content: [
                {
                  type: 'text',
                  text: 'score parameter is required for create_risk_snapshot',
                },
              ],
              isError: true,
            };
          }
          const snapshot = riskSnapshotRepo.create({
            engagementId,
            score,
            runId,
            openCritical,
            openHigh,
            openMedium,
            openLow,
            openInfo,
            openTotal,
            attackPathCount,
            exposedCredCount,
            modelVersion,
            attrsJson,
          });
          return {
            content: [{ type: 'text', text: JSON.stringify(snapshot, null, 2) }],
          };
        }

        case 'get_risk_snapshot': {
          if (!id) {
            return {
              content: [
                { type: 'text', text: 'id parameter is required for get_risk_snapshot' },
              ],
              isError: true,
            };
          }
          const snapshot = riskSnapshotRepo.findById(id);
          if (!snapshot) {
            return {
              content: [{ type: 'text', text: `Risk snapshot not found: ${id}` }],
              isError: true,
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(snapshot, null, 2) }] };
        }

        case 'list_risk_snapshots': {
          if (!engagementId) {
            return {
              content: [
                {
                  type: 'text',
                  text: 'engagementId parameter is required for list_risk_snapshots',
                },
              ],
              isError: true,
            };
          }
          const snapshots = riskSnapshotRepo.findByEngagement(engagementId, limit);
          return {
            content: [{ type: 'text', text: JSON.stringify(snapshots, null, 2) }],
          };
        }

        case 'latest_risk_snapshot': {
          if (!engagementId) {
            return {
              content: [
                {
                  type: 'text',
                  text: 'engagementId parameter is required for latest_risk_snapshot',
                },
              ],
              isError: true,
            };
          }
          const latest = riskSnapshotRepo.latest(engagementId);
          if (!latest) {
            return {
              content: [
                {
                  type: 'text',
                  text: `No risk snapshot found for engagement: ${engagementId}`,
                },
              ],
              isError: true,
            };
          }
          return { content: [{ type: 'text', text: JSON.stringify(latest, null, 2) }] };
        }
      }
    },
  );
}
