export type ActivityStatus = 'started' | 'completed' | 'failed';

export interface Activity {
  id: string;
  assessmentId: string;
  kind: string;
  command?: string;
  description: string;
  target?: string;
  status: ActivityStatus;
  startedAt: string;
  finishedAt?: string;
  resultSummary?: string;
  errorSummary?: string;
  createdAt: string;
}

export interface RecordActivityInput {
  assessmentId: string;
  kind: string;
  command?: string;
  description: string;
  target?: string;
  status?: ActivityStatus;
  startedAt?: string;
  finishedAt?: string;
  resultSummary?: string;
  errorSummary?: string;
}
