/**
 * sonobat - Entity type definitions
 *
 * These interfaces map 1:1 to the SQL tables defined in src/db/schema.ts.
 * Property names are camelCase conversions of the snake_case column names.
 *
 * Conventions:
 *   TEXT          -> string
 *   INTEGER       -> number
 *   REAL          -> number
 *   nullable col  -> optional property (?)
 *   All IDs       -> string (UUID)
 *   All timestamps -> string (ISO 8601)
 */

// ============================================================
// scans
// ============================================================

/** A single penetration-test execution unit. */
export interface Scan {
  id: string;
  startedAt: string;
  finishedAt?: string;
  notes?: string;
}

// ============================================================
// artifacts
// ============================================================

/** A reference to a raw tool output file (nmap XML, HTTP transaction, etc.). */
export interface Artifact {
  id: string;
  scanId?: string;
  tool: string;
  kind: string;
  path: string;
  sha256?: string;
  capturedAt: string;
  attrsJson?: string;
}

// ============================================================
// hosts
// ============================================================

/** A network host identified by IP address or domain name. */
export interface Host {
  id: string;
  authorityKind: string;
  authority: string;
  resolvedIpsJson: string;
  createdAt: string;
  updatedAt: string;
}

// ============================================================
// vhosts
// ============================================================

/** A virtual host associated with a host. */
export interface Vhost {
  id: string;
  hostId: string;
  hostname: string;
  source?: string;
  evidenceArtifactId: string;
  createdAt: string;
}

// ============================================================
// services
// ============================================================

/** A network service running on a host (e.g. HTTP on tcp/80). */
export interface Service {
  id: string;
  hostId: string;
  transport: string;
  port: number;
  appProto: string;
  protoConfidence: string;
  banner?: string;
  product?: string;
  version?: string;
  state: string;
  evidenceArtifactId: string;
  createdAt: string;
  updatedAt: string;
}

// ============================================================
// service_observations
// ============================================================

/** A key-value observation attached to a service. */
export interface ServiceObservation {
  id: string;
  serviceId: string;
  key: string;
  value: string;
  confidence: string;
  evidenceArtifactId: string;
  createdAt: string;
}

// ============================================================
// http_endpoints
// ============================================================

/** An HTTP endpoint discovered on a service. */
export interface HttpEndpoint {
  id: string;
  serviceId: string;
  vhostId?: string;
  baseUri: string;
  method: string;
  path: string;
  statusCode?: number;
  contentLength?: number;
  words?: number;
  lines?: number;
  evidenceArtifactId: string;
  createdAt: string;
}

// ============================================================
// inputs
// ============================================================

/** An input parameter (query, path, body, header, cookie) for a service. */
export interface Input {
  id: string;
  serviceId: string;
  location: string;
  name: string;
  typeHint?: string;
  createdAt: string;
  updatedAt: string;
}

// ============================================================
// endpoint_inputs
// ============================================================

/** A many-to-many link between an HTTP endpoint and an input parameter. */
export interface EndpointInput {
  id: string;
  endpointId: string;
  inputId: string;
  evidenceArtifactId: string;
  createdAt: string;
}

// ============================================================
// observations
// ============================================================

/** An observed value for an input parameter. */
export interface Observation {
  id: string;
  inputId: string;
  rawValue: string;
  normValue: string;
  bodyPath?: string;
  source: string;
  confidence: string;
  evidenceArtifactId: string;
  observedAt: string;
}

// ============================================================
// credentials
// ============================================================

/** A credential discovered for a service. */
export interface Credential {
  id: string;
  serviceId: string;
  endpointId?: string;
  username: string;
  secret: string;
  secretType: string;
  source: string;
  confidence: string;
  evidenceArtifactId: string;
  createdAt: string;
}

// ============================================================
// vulnerabilities
// ============================================================

/** A vulnerability identified on a service or endpoint. */
export interface Vulnerability {
  id: string;
  serviceId: string;
  endpointId?: string;
  vulnType: string;
  title: string;
  description?: string;
  severity: string;
  confidence: string;
  status: string;
  evidenceArtifactId: string;
  createdAt: string;
}

// ============================================================
// cves
// ============================================================

/** A CVE record associated with a vulnerability. */
export interface Cve {
  id: string;
  vulnerabilityId: string;
  cveId: string;
  description?: string;
  cvssScore?: number;
  cvssVector?: string;
  referenceUrl?: string;
  createdAt: string;
}

// ============================================================
// technique_docs
// ============================================================

/** A chunk of technique documentation indexed for full-text search. */
export interface TechniqueDoc {
  id: string;
  source: string;
  filePath: string;
  title: string;
  category: string;
  content: string;
  chunkIndex: number;
  indexedAt: string;
}
