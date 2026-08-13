import { describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { NodeRepository } from '../../../src/db/repository/node-repository.js';
import { EdgeRepository } from '../../../src/db/repository/edge-repository.js';

describe('Migration v8 HTTP graph model', () => {
  it('同一Network Endpointに複数HTTP Originと同一Pathを登録できる', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const nodes = new NodeRepository(db);
    const edges = new EdgeRepository(db);
    const host = nodes.create('host', { authorityKind: 'IP', authority: '10.0.0.1' });
    const network = nodes.create(
      'network_endpoint',
      { transport: 'tcp', port: 8443, state: 'open', protocolHint: 'https' },
      undefined,
      host.id,
    );
    edges.create('HOST_NETWORK_ENDPOINT', host.id, network.id);
    const originA = nodes.create(
      'http_origin',
      { scheme: 'https', hostname: 'a.example.test', port: 8443 },
      undefined,
      network.id,
    );
    const originB = nodes.create(
      'http_origin',
      { scheme: 'https', hostname: 'b.example.test', port: 8443 },
      undefined,
      network.id,
    );
    const endpointA = nodes.create(
      'web_endpoint',
      { method: 'GET', path: '/admin' },
      undefined,
      originA.id,
    );
    const endpointB = nodes.create(
      'web_endpoint',
      { method: 'GET', path: '/admin' },
      undefined,
      originB.id,
    );

    expect(originA.naturalKey).not.toBe(originB.naturalKey);
    expect(endpointA.naturalKey).not.toBe(endpointB.naturalKey);
  });

  it('異なるWeb Endpointにある同名Inputを区別する', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const nodes = new NodeRepository(db);
    const first = nodes.create('input', { location: 'query', name: 'id' }, undefined, 'web-1');
    const second = nodes.create('input', { location: 'query', name: 'id' }, undefined, 'web-2');
    expect(first.naturalKey).not.toBe(second.naturalKey);
  });
});
