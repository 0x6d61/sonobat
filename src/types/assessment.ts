export interface Assessment {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateAssessmentInput {
  name: string;
}
