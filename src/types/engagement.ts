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
