/**
 * sonobat — Graph type system
 *
 * グラフネイティブスキーマの型定義。
 * NodeKind/EdgeKind 列挙、Zod props スキーマ、
 * GraphNode/GraphEdge インターフェース、natural key builder。
 */

import { z } from 'zod';
import { randomUUID } from 'node:crypto';

// ============================================================
// NodeKind / EdgeKind 列挙
// ============================================================

export const NODE_KINDS = [
  'host',
  'vhost',
  'service',
  'endpoint',
  'input',
  'observation',
  'credential',
  'vulnerability',
  'cve',
  'svc_observation',
] as const;
export type NodeKind = (typeof NODE_KINDS)[number];

export const EDGE_KINDS = [
  'HOST_SERVICE',
  'HOST_VHOST',
  'SERVICE_ENDPOINT',
  'SERVICE_INPUT',
  'SERVICE_CREDENTIAL',
  'SERVICE_VULNERABILITY',
  'SERVICE_OBSERVATION',
  'ENDPOINT_INPUT',
  'ENDPOINT_VULNERABILITY',
  'ENDPOINT_CREDENTIAL',
  'INPUT_OBSERVATION',
  'VULNERABILITY_CVE',
  'VHOST_ENDPOINT',
] as const;
export type EdgeKind = (typeof EDGE_KINDS)[number];

// ============================================================
// Zod Props スキーマ
// ============================================================

export const HostPropsSchema = z.object({
  authorityKind: z.enum(['IP', 'DOMAIN']),
  authority: z.string().min(1),
  resolvedIpsJson: z.string().default('[]'),
});
export type HostProps = z.infer<typeof HostPropsSchema>;

export const VhostPropsSchema = z.object({
  hostname: z.string().min(1),
  source: z.string().optional(),
});
export type VhostProps = z.infer<typeof VhostPropsSchema>;

export const ServicePropsSchema = z.object({
  transport: z.string().min(1),
  port: z.number().int().nonnegative(),
  appProto: z.string().min(1),
  protoConfidence: z.string().min(1),
  banner: z.string().optional(),
  product: z.string().optional(),
  version: z.string().optional(),
  state: z.string().min(1),
});
export type ServiceProps = z.infer<typeof ServicePropsSchema>;

export const EndpointPropsSchema = z.object({
  baseUri: z.string().min(1),
  method: z.string().min(1),
  path: z.string().min(1),
  statusCode: z.number().int().optional(),
  contentLength: z.number().int().optional(),
  words: z.number().int().optional(),
  lines: z.number().int().optional(),
});
export type EndpointProps = z.infer<typeof EndpointPropsSchema>;

export const InputPropsSchema = z.object({
  location: z.string().min(1),
  name: z.string().min(1),
  typeHint: z.string().optional(),
});
export type InputProps = z.infer<typeof InputPropsSchema>;

export const ObservationPropsSchema = z.object({
  rawValue: z.string(),
  normValue: z.string(),
  bodyPath: z.string().optional(),
  source: z.string().min(1),
  confidence: z.string().min(1),
  observedAt: z.string().min(1),
});
export type ObservationProps = z.infer<typeof ObservationPropsSchema>;

export const CredentialPropsSchema = z.object({
  username: z.string(),
  secret: z.string(),
  secretType: z.string().min(1),
  source: z.string().min(1),
  confidence: z.string().min(1),
});
export type CredentialProps = z.infer<typeof CredentialPropsSchema>;

export const VulnerabilityPropsSchema = z.object({
  vulnType: z.string().min(1),
  title: z.string().min(1),
  description: z.string().optional(),
  severity: z.string().min(1),
  confidence: z.string().min(1),
  status: z.string().min(1).default('unverified'),
});
export type VulnerabilityProps = z.infer<typeof VulnerabilityPropsSchema>;

export const CvePropsSchema = z.object({
  cveId: z.string().min(1),
  description: z.string().optional(),
  cvssScore: z.number().optional(),
  cvssVector: z.string().optional(),
  referenceUrl: z.string().optional(),
});
export type CveProps = z.infer<typeof CvePropsSchema>;

export const SvcObservationPropsSchema = z.object({
  key: z.string().min(1),
  value: z.string(),
  confidence: z.string().min(1),
});
export type SvcObservationProps = z.infer<typeof SvcObservationPropsSchema>;

/** NodeKind → Zod スキーマのマッピング */
const PROPS_SCHEMA_MAP: Record<NodeKind, z.ZodTypeAny> = {
  host: HostPropsSchema,
  vhost: VhostPropsSchema,
  service: ServicePropsSchema,
  endpoint: EndpointPropsSchema,
  input: InputPropsSchema,
  observation: ObservationPropsSchema,
  credential: CredentialPropsSchema,
  vulnerability: VulnerabilityPropsSchema,
  cve: CvePropsSchema,
  svc_observation: SvcObservationPropsSchema,
};

// ============================================================
// GraphNode / GraphEdge インターフェース
// ============================================================

export interface GraphNode {
  id: string;
  kind: NodeKind;
  naturalKey: string;
  propsJson: string;
  evidenceArtifactId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface GraphEdge {
  id: string;
  kind: EdgeKind;
  sourceId: string;
  targetId: string;
  propsJson: string;
  evidenceArtifactId?: string;
  createdAt: string;
}

// ============================================================
// validateProps
// ============================================================

export type ValidateResult = { ok: true; data: unknown } | { ok: false; error: string };

/**
 * 指定された NodeKind に対する props のバリデーション。
 */
export function validateProps(kind: NodeKind, props: unknown): ValidateResult {
  const schema = PROPS_SCHEMA_MAP[kind];
  const result = schema.safeParse(props);
  if (result.success) {
    return { ok: true, data: result.data };
  }
  return { ok: false, error: result.error.message };
}

// ============================================================
// buildNaturalKey
// ============================================================

/**
 * ノード種別と props から自然キーを構築する。
 *
 * 決定的なキーが生成できるノード (host, vhost, service, endpoint, input, cve) は
 * 常に同じ入力に対して同じキーを返す。
 *
 * 一意性が保証できないノード (observation, credential, vulnerability, svc_observation)
 * は UUID ベースのキーを生成する。
 *
 * @param kind      ノード種別
 * @param props     ノードの props（部分的でも可）
 * @param parentId  親ノードの ID（vhost, service, endpoint, input, cve で必須）
 */
export function buildNaturalKey(kind: NodeKind, props: unknown, parentId?: string): string {
  const p = props as Record<string, unknown>;

  switch (kind) {
    case 'host':
      return `host:${p.authority}`;

    case 'vhost':
      return `vhost:${parentId}:${p.hostname}`;

    case 'service':
      return `svc:${parentId}:${p.transport}:${p.port}`;

    case 'endpoint':
      return `ep:${parentId}:${p.method}:${p.path}`;

    case 'input':
      return `in:${parentId}:${p.location}:${p.name}`;

    case 'cve':
      return `cve:${parentId}:${p.cveId}`;

    case 'observation':
      return `obs:${randomUUID()}`;

    case 'credential':
      return `cred:${randomUUID()}`;

    case 'vulnerability':
      return `vuln:${randomUUID()}`;

    case 'svc_observation':
      return `svcobs:${randomUUID()}`;
  }
}
