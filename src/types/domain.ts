export type McpProfile = 'tactical' | 'worker';

export interface Entity {
  id: string;
  kind: string;
  naturalKey: string;
  properties: Record<string, unknown>;
  artifactId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Relation {
  id: string;
  kind: string;
  sourceEntityId: string;
  targetEntityId: string;
  properties: Record<string, unknown>;
  artifactId?: string;
  createdAt: string;
}

export interface Artifact {
  id: string;
  actionId: string;
  path: string;
}

export interface AttackHypothesis {
  id: string;
  engagementId: string;
  missionId?: string;
  title: string;
  objective: string;
  status: string;
  preconditions: unknown[];
  blockers: unknown[];
  validationResult: Record<string, unknown>;
  dismissalReason?: string;
  artifactId?: string;
  createdAt: string;
  updatedAt: string;
}
