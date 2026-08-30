# sonobat

[![CI](https://github.com/0x6d61/sonobat/actions/workflows/ci.yml/badge.svg)](https://github.com/0x6d61/sonobat/actions/workflows/ci.yml)

Sonobat is an MCP server for storing and recalling investigation state during an authorized penetration test.
It is external working memory for an AI agent.

Sonobat stores facts, relationships, investigation history, and references to raw evidence.
The agent plans, decides, executes tools, and interprets results.
Sonobat does not plan investigations or execute attack tools.

## Core model

~~~text
Assessment
│
├── Entity ─ Relation ─ Entity
├── Activity
└── Artifact
~~~

- **Assessment** is the namespace for one HTB machine or penetration-test engagement.
- **Entity** is a confirmed target fact such as a host, port, service, endpoint, account, credential, or vulnerability.
- **Relation** is a confirmed relationship between two Entities.
- **Activity** records an investigation that was attempted, its sanitized command when available, and its result.
- **Artifact** stores a safe, root-relative reference to raw output such as an nmap file or HTTP response.

Mission, Action queue, Worker, Planner, Agent role, Lease, retry strategy, approval workflow, Hypothesis, and LLM thought storage are not part of Sonobat.

## Supported Entity kinds

The current SQLite schema accepts these Entity kinds:

- `ip_address`: a confirmed IP address.
- `host`: a host identified by address or name.
- `virtual_host`: a name-based virtual host or HTTP Host authority.
- `network_endpoint`: a transport endpoint exposed by a host.
- `service`: a service running on a network endpoint.
- `application`: an identified web or other application.
- `web_endpoint`: an HTTP method and path exposed by an application.
- `account`: an identified user or service account.
- `credential`: a credential associated with an account or service.
- `vulnerability`: a confirmed weakness.

Vhosts use `kind: "virtual_host"` and should include scheme, hostname, and port in their properties.
Use a natural key such as `vhost:https://app.example.com:443` when the origin is HTTPS on port 443.

## MCP tools

The server exposes the same core tools to every client.
There are no tactical or worker profiles.

- **assessments**: create and inspect Assessment namespaces, including a combined `get_context` read.
- **mutate**: upsert an Entity or Relation inside an Assessment.
- **query**: list and inspect Entities, Relations, and Artifact references inside an Assessment.
- **activities**: record and query investigation history.
- **artifacts**: register and query raw evidence references.

Every graph and evidence operation is scoped by `assessmentId`.
When a database contains exactly one Assessment, repository-level compatibility calls may omit the scope.

## Investigation cycle

1. The agent reads the current Assessment state.
2. The agent decides what to investigate and executes the external tool itself.
3. The agent registers raw output as an Artifact.
4. The agent stores confirmed facts and relationships as Entity and Relation values.
5. The agent records the attempted investigation as an Activity.
6. The agent reads the updated state before deciding what to do next.

## Artifacts

Tool output and large files stay outside SQLite.
The `artifacts` table stores the Assessment, optional Activity, relative path, media type, hash, and capture timestamps.
The default root is `~/.sonobat/artifacts/` and can be changed with `SONOBAT_ARTIFACT_DIR`.
Absolute paths and paths that escape this root are rejected.

## Setup

Requirements:

- Node.js 20 or later
- npm
- a build environment supported by better-sqlite3

~~~bash
git clone https://github.com/0x6d61/sonobat.git
cd sonobat
npm ci
npm run build
~~~

Start the server:

~~~bash
SONOBAT_DB_PATH=sonobat.db npm run dev
~~~

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| **SONOBAT_DB_PATH** | sonobat.db | SQLite database path |
| **SONOBAT_ARTIFACT_DIR** | ~/.sonobat/artifacts/ | Artifact root |

## Development

~~~bash
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
~~~

Architecture and terminology are maintained in the [Sonobat Wiki](https://github.com/0x6d61/sonobat/wiki).

## License

ISC
