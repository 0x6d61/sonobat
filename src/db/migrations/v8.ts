import type Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import type { Migration } from './index.js';

interface LegacyService {
  id: string;
  props_json: string;
  evidence_artifact_id: string | null;
  created_at: string;
  updated_at: string;
  host_id: string;
}

interface LegacyEndpoint {
  id: string;
  props_json: string;
  evidence_artifact_id: string | null;
  created_at: string;
  updated_at: string;
  service_id: string;
}

const migration: Migration = {
  version: 8,
  description: 'Add Network Endpoint, HTTP Origin, and Web Endpoint graph model',
  up(db: Database.Database): void {
    db.exec(`
      INSERT INTO graph_node_kinds (kind, description) VALUES
        ('network_endpoint', 'Transport endpoint exposed by a host'),
        ('http_origin', 'HTTP origin served by a network endpoint'),
        ('web_endpoint', 'HTTP method and path within an origin');
      INSERT INTO graph_edge_kinds (kind, description) VALUES
        ('HOST_NETWORK_ENDPOINT', 'Host exposes network endpoint'),
        ('NETWORK_ENDPOINT_HTTP_ORIGIN', 'Network endpoint serves HTTP origin'),
        ('HTTP_ORIGIN_WEB_ENDPOINT', 'HTTP origin exposes Web endpoint');
    `);

    const services = db
      .prepare(
        `SELECT n.*, e.source_id host_id FROM nodes n
         JOIN edges e ON e.target_id = n.id AND e.kind = 'HOST_SERVICE'
         WHERE n.kind = 'service'`,
      )
      .all() as LegacyService[];
    const serviceMap = new Map<string, string>();
    for (const service of services) {
      const props = JSON.parse(service.props_json) as Record<string, unknown>;
      const id = randomUUID();
      serviceMap.set(service.id, id);
      db.prepare(`INSERT INTO nodes VALUES (?, 'network_endpoint', ?, ?, ?, ?, ?)`).run(
        id,
        `net:${service.host_id}:${props.transport}:${props.port}`,
        JSON.stringify({
          transport: props.transport,
          port: props.port,
          state: props.state,
          protocolHint: props.appProto,
          banner: props.banner,
          product: props.product,
          version: props.version,
        }),
        service.evidence_artifact_id,
        service.created_at,
        service.updated_at,
      );
      db.prepare(`INSERT INTO edges VALUES (?, 'HOST_NETWORK_ENDPOINT', ?, ?, '{}', ?, ?)`).run(
        randomUUID(),
        service.host_id,
        id,
        service.evidence_artifact_id,
        service.created_at,
      );
    }

    const endpoints = db
      .prepare(
        `SELECT n.*, e.source_id service_id FROM nodes n
         JOIN edges e ON e.target_id = n.id AND e.kind = 'SERVICE_ENDPOINT'
         WHERE n.kind = 'endpoint'`,
      )
      .all() as LegacyEndpoint[];
    for (const endpoint of endpoints) {
      const networkId = serviceMap.get(endpoint.service_id);
      if (networkId === undefined) continue;
      const props = JSON.parse(endpoint.props_json) as Record<string, unknown>;
      const url = new URL(String(props.baseUri));
      const port = url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number(url.port);
      const originKey = `origin:${networkId}:${url.protocol.slice(0, -1)}:${url.hostname}:${port}`;
      let origin = db.prepare('SELECT id FROM nodes WHERE natural_key = ?').get(originKey) as
        | { id: string }
        | undefined;
      if (origin === undefined) {
        origin = { id: randomUUID() };
        db.prepare(`INSERT INTO nodes VALUES (?, 'http_origin', ?, ?, ?, ?, ?)`).run(
          origin.id,
          originKey,
          JSON.stringify({ scheme: url.protocol.slice(0, -1), hostname: url.hostname, port }),
          endpoint.evidence_artifact_id,
          endpoint.created_at,
          endpoint.updated_at,
        );
        db.prepare(
          `INSERT INTO edges VALUES (?, 'NETWORK_ENDPOINT_HTTP_ORIGIN', ?, ?, '{}', ?, ?)`,
        ).run(
          randomUUID(),
          networkId,
          origin.id,
          endpoint.evidence_artifact_id,
          endpoint.created_at,
        );
      }
      const webId = randomUUID();
      db.prepare(`INSERT INTO nodes VALUES (?, 'web_endpoint', ?, ?, ?, ?, ?)`).run(
        webId,
        `webep:${origin.id}:${props.method}:${props.path}`,
        JSON.stringify({
          method: props.method,
          path: props.path,
          statusCode: props.statusCode,
          contentLength: props.contentLength,
        }),
        endpoint.evidence_artifact_id,
        endpoint.created_at,
        endpoint.updated_at,
      );
      db.prepare(`INSERT INTO edges VALUES (?, 'HTTP_ORIGIN_WEB_ENDPOINT', ?, ?, '{}', ?, ?)`).run(
        randomUUID(),
        origin.id,
        webId,
        endpoint.evidence_artifact_id,
        endpoint.created_at,
      );
    }
  },
};

export default migration;
