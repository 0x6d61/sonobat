export interface Entity {
  id: string;
  assessmentId: string;
  kind: string;
  naturalKey: string;
  properties: Record<string, unknown>;
  artifactId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Relation {
  id: string;
  assessmentId: string;
  kind: string;
  sourceEntityId: string;
  targetEntityId: string;
  properties: Record<string, unknown>;
  artifactId?: string;
  createdAt: string;
}

export interface Artifact {
  id: string;
  assessmentId: string;
  activityId?: string;
  path: string;
  mediaType?: string;
  sha256?: string;
  capturedAt: string;
  createdAt: string;
}
