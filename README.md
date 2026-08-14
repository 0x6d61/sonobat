# sonobat

[![CI](https://github.com/0x6d61/sonobat/actions/workflows/ci.yml/badge.svg)](https://github.com/0x6d61/sonobat/actions/workflows/ci.yml)

Sonobat is an MCP server that shares penetration-testing operations, target data, evaluations, and Artifact references between a tactical controller and Workers.

## Domain model

~~~text
Operations
 Engagement
  └─ Mission
      └─ Action
          └─ Child Action

Attack Data Graph
 Entity ─ Relation ─ Entity

Evaluation
 Attack Hypothesis
  └─ Hypothesis Event

Evidence reference
 Action ─ Artifact path
~~~

Run, Execution, Observation, Node, and Edge are not part of the current model.

Entity and Relation kinds are registered by SQLite migrations.
Credentials use one **credential** Entity kind.
Passwords, password hashes, private keys, API keys, and tokens are distinguished by **Credential.kind**.
An authorized MCP query returns **Credential.value** without masking.
Sonobat does not copy Credential values into server logs or MCP errors.

## MCP profiles

Every server process requires **SONOBAT_PROFILE=tactical** or **SONOBAT_PROFILE=worker**.
There is no full profile.

The tactical profile exposes:

- **engagements**
- **missions**
- **actions**
- **query**
- **mutate**
- **evaluations**
- **search_kb**
- **index_kb**

The worker profile exposes:

- **worker**
- **query**
- **mutate**
- **evaluations**

The **query** tool includes **list_artifacts** for retrieving the relative Artifact paths owned by an Action.

The Worker can lease only Action kinds listed in **poll_action**.
It can renew or finish its lease, register Artifact paths, and propose a child Action.
A proposed child Action is not available to another Worker until the tactical controller adopts it.

Sonobat does not start SubAgents or execute external commands.

## Artifacts

Tool output and large files stay outside SQLite.
The **artifacts** table stores only:

~~~text
id
action_id
path
~~~

**path** is relative to **SONOBAT_ARTIFACT_DIR**.
The default root is **~/.sonobat/artifacts/**.
Absolute paths and paths that escape this root are rejected.

Workers write files into the Artifact root before registering the relative path.

Typical Artifact files include:

- Nmap, ffuf, and linPEAS output
- raw HTTP responses
- exploit stdout and stderr
- PCAP files
- acquired source code
- dictionaries
- screenshots
- session logs

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

Start a tactical server:

~~~bash
SONOBAT_PROFILE=tactical npm run dev
~~~

Start a Worker server against the same database:

~~~bash
SONOBAT_PROFILE=worker npm run dev
~~~

## Agent Skill example

Connecting an MCP server does not guarantee that an Agent will use it consistently.
The repository includes an example Skill that makes Sonobat reads and writes part of the Agent workflow:

- [examples/use-sonobat/SKILL.md](examples/use-sonobat/SKILL.md)

Install or copy the `examples/use-sonobat` directory into the Skill location supported by the Agent platform.
Give a tactical Agent only the tactical MCP connection and a Worker only the worker MCP connection.
The Skill requires the Agent to read Sonobat before planning, register results before completing work, and stop when the expected profile is unavailable.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| **SONOBAT_PROFILE** | none | Required MCP profile: tactical or worker |
| **SONOBAT_DB_PATH** | sonobat.db | SQLite database path |
| **SONOBAT_ARTIFACT_DIR** | ~/.sonobat/artifacts/ | Artifact root |
| **SONOBAT_DATA_DIR** | ~/.sonobat/data/ | Knowledge-base data root |

The two profiles can share **SONOBAT_DB_PATH**.
Use separate MCP connection definitions so a Worker process cannot call tactical-only tools.

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
