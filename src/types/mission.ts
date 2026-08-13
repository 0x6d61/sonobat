import { z } from 'zod';

export const TargetRefSchema = z.object({
  type: z.enum(['node', 'finding', 'action']),
  id: z.string().min(1),
});
export type TargetRef = z.infer<typeof TargetRefSchema>;

export const TargetsSchema = z.array(TargetRefSchema);

export const ActionParamsSchema = z
  .object({
    objective: z.string().min(1).optional(),
    targets: TargetsSchema.optional(),
    expectedOutputs: z.array(z.string().min(1)).optional(),
    stopConditions: z.array(z.string().min(1)).optional(),
  })
  .passthrough();

export const EngagementScopeSchema = z
  .object({
    nodeIds: z.array(z.string().min(1)).optional(),
    hostAuthorities: z.array(z.string().min(1)).optional(),
  })
  .passthrough();
