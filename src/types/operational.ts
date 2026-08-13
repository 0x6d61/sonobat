/**
 * sonobat — Operational entity types
 *
 * v5 運用テーブル（engagements, runs, action_queue, action_executions,
 * findings, finding_events, risk_snapshots）のエンティティ型定義。
 */

// ============================================================
// Engagement
// ============================================================

export interface Engagement {
  id: string;
  name: string;
  environment: string;
  scopeJson: string;
  policyJson: string;
  scheduleCron?: string;
  status: string;
  createdAt: string;
  updatedAt: string;
}

export type CreateEngagementInput = {
  name: string;
  environment?: string;
  scopeJson?: string;
  policyJson?: string;
  scheduleCron?: string;
  status?: string;
};

// ============================================================
// Run
// ============================================================

export interface Run {
  id: string;
  engagementId: string;
  triggerKind: string;
  triggerRef?: string;
  status: string;
  startedAt?: string;
  finishedAt?: string;
  summaryJson: string;
  createdAt: string;
}

export type CreateRunInput = {
  engagementId: string;
  triggerKind: string;
  triggerRef?: string;
  status: string;
};

// ============================================================
// Mission
// ============================================================

export interface Mission {
  id: string;
  engagementId: string;
  runId?: string;
  objective: string;
  targetsJson: string;
  successConditionsJson: string;
  stopConditionsJson: string;
  status: string;
  createdAt: string;
  completedAt?: string;
}

export type CreateMissionInput = {
  engagementId: string;
  runId?: string;
  objective: string;
  targetsJson?: string;
  successConditionsJson?: string;
  stopConditionsJson?: string;
  status?: string;
};

export interface ObservationRecord {
  id: string;
  artifactId: string;
  actor: string;
  contentJson: string;
  confidence?: number;
  nodeIds: string[];
  edgeIds: string[];
  findingIds: string[];
  createdAt: string;
}

export interface Artifact {
  id: string;
  engagementId?: string;
  runId?: string;
  missionId?: string;
  actionId?: string;
  actionExecutionId?: string;
  producer: string;
  kind: string;
  path: string;
  sha256?: string;
  mediaType?: string;
  sensitivity: string;
  attrsJson: string;
  capturedAt: string;
}

export type RegisterArtifactInput = {
  executionId: string;
  leaseOwner: string;
  kind: string;
  path: string;
  sha256?: string;
  mediaType?: string;
  sensitivity?: string;
  attrsJson?: string;
  contentBase64?: string;
};

// ============================================================
// ActionQueueItem
// ============================================================

export interface ActionQueueItem {
  id: string;
  engagementId: string;
  missionId?: string;
  runId?: string;
  parentActionId?: string;
  kind: string;
  priority: number;
  dedupeKey: string;
  paramsJson: string;
  state: string;
  attemptCount: number;
  maxAttempts: number;
  availableAt: string;
  leaseOwner?: string;
  leaseExpiresAt?: string;
  lastError?: string;
  createdAt: string;
  updatedAt: string;
}

export type CreateActionInput = {
  engagementId: string;
  missionId?: string;
  runId?: string;
  parentActionId?: string;
  kind: string;
  priority?: number;
  dedupeKey: string;
  paramsJson?: string;
  state?: string;
  maxAttempts?: number;
  availableAt?: string;
};

// ============================================================
// ActionExecution
// ============================================================

export interface ActionExecution {
  id: string;
  actionId: string;
  runId?: string;
  executor: string;
  command?: string;
  inputJson: string;
  outputJson: string;
  stdoutArtifactId?: string;
  stderrArtifactId?: string;
  exitCode?: number;
  errorType?: string;
  errorMessage?: string;
  startedAt: string;
  finishedAt?: string;
  durationMs?: number;
}

export type CreateExecutionInput = {
  actionId: string;
  runId?: string;
  executor: string;
  command?: string;
  inputJson?: string;
};

// ============================================================
// Finding
// ============================================================

export interface Finding {
  id: string;
  engagementId: string;
  canonicalKey: string;
  nodeId?: string;
  title: string;
  severity: string;
  confidence: string;
  state: string;
  stateReason?: string;
  owner?: string;
  ticketRef?: string;
  firstSeenRunId?: string;
  lastSeenRunId?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  slaDueAt?: string;
  attrsJson: string;
}

export type UpsertFindingInput = {
  engagementId: string;
  canonicalKey: string;
  nodeId?: string;
  title: string;
  severity: string;
  confidence: string;
  state?: string;
  runId?: string;
  attrsJson?: string;
  artifactId?: string;
};

// ============================================================
// FindingEvent
// ============================================================

export interface FindingEvent {
  id: string;
  findingId: string;
  runId?: string;
  eventType: string;
  beforeJson: string;
  afterJson: string;
  artifactId?: string;
  createdAt: string;
}

export type CreateFindingEventInput = {
  eventType: string;
  runId?: string;
  beforeJson?: string;
  afterJson?: string;
  artifactId?: string;
};

// ============================================================
// RiskSnapshot
// ============================================================

export interface RiskSnapshot {
  id: string;
  engagementId: string;
  runId?: string;
  score: number;
  openCritical: number;
  openHigh: number;
  openMedium: number;
  openLow: number;
  openInfo: number;
  openTotal: number;
  attackPathCount: number;
  exposedCredCount: number;
  modelVersion?: string;
  attrsJson: string;
  createdAt: string;
}

export type CreateRiskSnapshotInput = {
  engagementId: string;
  runId?: string;
  score: number;
  openCritical?: number;
  openHigh?: number;
  openMedium?: number;
  openLow?: number;
  openInfo?: number;
  openTotal?: number;
  attackPathCount?: number;
  exposedCredCount?: number;
  modelVersion?: string;
  attrsJson?: string;
};
