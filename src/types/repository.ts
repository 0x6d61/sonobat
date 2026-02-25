/**
 * sonobat - Repository input / update type definitions
 *
 * Create types use `Omit` to strip auto-generated columns (id, createdAt, updatedAt).
 * Update types use `Partial<Pick<...>>` to allow selective field updates.
 */

import type {
  Artifact,
  Credential,
  Cve,
  EndpointInput,
  Host,
  HttpEndpoint,
  Input,
  Observation,
  Scan,
  Service,
  ServiceObservation,
  Vhost,
  Vulnerability,
} from './entities.js';

// ============================================================
// Create input types
// ============================================================

/** Input for creating a new Scan. */
export type CreateScanInput = Omit<Scan, 'id'>;

/** Input for creating a new Artifact. */
export type CreateArtifactInput = Omit<Artifact, 'id'>;

/** Input for creating a new Host. */
export type CreateHostInput = Omit<Host, 'id' | 'createdAt' | 'updatedAt'>;

/** Input for creating a new Vhost. */
export type CreateVhostInput = Omit<Vhost, 'id' | 'createdAt'>;

/** Input for creating a new Service. */
export type CreateServiceInput = Omit<Service, 'id' | 'createdAt' | 'updatedAt'>;

/** Input for creating a new ServiceObservation. */
export type CreateServiceObservationInput = Omit<ServiceObservation, 'id' | 'createdAt'>;

/** Input for creating a new HttpEndpoint. */
export type CreateHttpEndpointInput = Omit<HttpEndpoint, 'id' | 'createdAt'>;

/** Input for creating a new Input. */
export type CreateInputInput = Omit<Input, 'id' | 'createdAt' | 'updatedAt'>;

/** Input for creating a new EndpointInput. */
export type CreateEndpointInputInput = Omit<EndpointInput, 'id' | 'createdAt'>;

/** Input for creating a new Observation. */
export type CreateObservationInput = Omit<Observation, 'id'>;

/** Input for creating a new Credential. */
export type CreateCredentialInput = Omit<Credential, 'id' | 'createdAt'>;

/** Input for creating a new Vulnerability. */
export type CreateVulnerabilityInput = Omit<Vulnerability, 'id' | 'createdAt'>;

/** Input for creating a new Cve. */
export type CreateCveInput = Omit<Cve, 'id' | 'createdAt'>;

// ============================================================
// Update input types (only for entities with updatedAt)
// ============================================================

/** Input for updating an existing Host. */
export type UpdateHostInput = Partial<Pick<Host, 'resolvedIpsJson'>>;

/** Input for updating an existing Service. */
export type UpdateServiceInput = Partial<
  Pick<Service, 'appProto' | 'protoConfidence' | 'banner' | 'product' | 'version' | 'state'>
>;

/** Input for updating an existing Input. */
export type UpdateInputInput = Partial<Pick<Input, 'typeHint'>>;
