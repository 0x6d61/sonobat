# sonobat

[![CI](https://github.com/0x6d61/sonobat/actions/workflows/ci.yml/badge.svg)](https://github.com/0x6d61/sonobat/actions/workflows/ci.yml)

**AttackDataGraph for autonomous penetration testing.**

sonobat is an MCP server for sharing missions, actions, attack data, and artifact provenance between a tactical controller and workers. Workers interpret arbitrary tool output and record observations that update the graph atomically.

## Features

- **Mission Tree** — Organize tactical objectives, actions, and derived child actions
- **Artifact Tree** — Trace observations and graph changes back to executions and artifacts
- **Observation** — Apply an artifact interpretation and graph changes in one transaction
- **Graph-Native Schema** — Generic `nodes` + `edges` tables with Zod-validated, Migration-defined kinds
- **Propose** — Gap-driven engine suggests what to scan next based on missing data
- **Graph Traversal** — SQLite recursive CTE queries for attack path analysis with preset patterns
- **Knowledge Base** — HackTricks documentation with auto-clone, incremental indexing, and FTS5 full-text search
- **Continuous Pentest** — Engagement/run lifecycle, action queue with deduplication, finding tracking with state machine, and time-series risk snapshots
- **MCP Server** — 10 tools + 4 resources accessible via stdio

## Data Model

```
nodes (kind + props_json)
 ├── host         — IP or domain target
 ├── vhost        — Virtual host
 ├── service      — Transport + port + protocol
 ├── endpoint     — HTTP method + path
 ├── input        — Parameter (query, body, header, etc.)
 ├── observation   — Observed value for an input
 ├── credential   — Username + secret
 ├── vulnerability — Detected vulnerability
 ├── cve          — CVE record
 └── svc_observation — Service-level key-value observation
 ├── network_endpoint — Transport + port exposed by a host
 ├── http_origin    — Scheme + hostname + port served by a network endpoint
 └── web_endpoint   — HTTP method + path within an origin

edges (kind + source_id + target_id)
 HOST_SERVICE, HOST_VHOST, SERVICE_ENDPOINT, SERVICE_INPUT,
 SERVICE_CREDENTIAL, SERVICE_VULNERABILITY, SERVICE_OBSERVATION,
 ENDPOINT_INPUT, ENDPOINT_VULNERABILITY, ENDPOINT_CREDENTIAL,
 INPUT_OBSERVATION, VULNERABILITY_CVE, VHOST_ENDPOINT
```

Every node can be linked to an **Artifact** (evidence), ensuring full traceability.

### Operational Tables (v0.5.0)

```
engagements        — Long-lived assessment context (STG continuous testing)
 └── runs          — Execution cycle (manual/scheduled/event-triggered)
      ├── missions           — Tactical objectives and completion criteria
      │    └── action_queue  — Worker-sized actions with priority queue + deduplication
      │    └── action_executions — Attempt history and outcomes
      ├── findings           — Vulnerability lifecycle (open → fixed/accepted_risk)
      │    └── finding_events — Immutable state transition log
      └── risk_snapshots     — Time-series risk metrics for trend analysis
```

`scans` and `artifacts` gain `engagement_id` / `run_id` lineage columns for full traceability.

## Quick Start

### Prerequisites

- Node.js >= 20 LTS
- npm

### Install & Build

```bash
git clone https://github.com/0x6d61/sonobat.git
cd sonobat
npm install
npm run build
```

### Run Tests

```bash
npm test
```

## MCP Server

sonobat runs as an MCP server over stdio. Tactical controllers and workers use the same server to manage missions and actions, query the graph, and record artifact-backed observations.

### Available Tools (10)

| Tool | Actions / Description |
|------|----------------------|
| **`query`** | `list_nodes` — List nodes by kind with optional JSON filters |
| | `get_node` — Get node detail with adjacent edges and neighbors |
| | `traverse` — Recursive graph traversal with depth/edge-kind filters |
| | `summary` — Node and edge counts by kind |
| | `attack_paths` — Preset pattern analysis (attack_surface, critical_vulns, etc.) |
| **`mutate`** | `add_node` — Create or upsert a node with validated props |
| | `add_edge` — Create an edge between two nodes |
| | `update_node` — Partial update of node props |
| | `delete_node` — Delete a node (cascades to edges) |
| **`propose`** | Suggest next actions based on missing data in the graph |
| **`search_kb`** | Full-text search the HackTricks knowledge base |
| **`index_kb`** | Auto-clone/pull HackTricks and incrementally index documentation |
| **`ops`** | Manage engagements, runs, actions, leases, and executions |
| **`findings`** | Manage findings and risk snapshots |
| **`missions`** | Create and complete missions, inspect Mission Trees, and retrieve Action Context |
| **`observe`** | Record an artifact interpretation and apply graph changes atomically |
| **`worker`** | Start an Action execution, register Artifacts, and finish the Execution and Action atomically |

`poll_action` requires the Action kinds supported by the Worker. The `worker` tool can renew an active lease while a long-running Action is in progress.

### Attack Path Presets

| Pattern | Description |
|---------|-------------|
| `attack_surface` | Host → endpoint + input complete paths |
| `critical_vulns` | Host → service → vulnerability (critical/high severity) |
| `credential_exposure` | Service → credential mappings |
| `unscanned_services` | Services with no endpoints discovered |
| `vuln_by_host` | Vulnerability count by host |
| `reachable_services` | All services reachable from a host |

### MCP Resources (4)

| URI | Description |
|-----|-------------|
| `sonobat://nodes` | Node list (optionally filter by kind) |
| `sonobat://nodes/{id}` | Node detail with edges and neighbors |
| `sonobat://summary` | Overall statistics |
| `sonobat://techniques/categories` | Knowledge base categories |

## Propose Engine

The proposer analyzes missing data in the attack graph and suggests next actions:

| Missing Data Pattern | Proposed Action | Description |
|---------------------|----------------|-------------|
| Host has no services | `network_service_discovery` | Discover exposed network services |
| HTTP service has no endpoints | `web_endpoint_discovery` | Discover Web endpoints |
| Endpoint has no inputs | `parameter_discovery` | Find input parameters |
| Input has no observations | `value_collection` | Collect parameter values |
| Input has observations but no vulnerabilities | `value_fuzz` | Fuzz the parameter with attack payloads |
| HTTP service has no vhosts | `vhost_discovery` | Virtual host enumeration |
| HTTP service has no recorded vulnerability | `vulnerability_discovery` | Discover known vulnerabilities |

## Knowledge Base (HackTricks)

sonobat includes a built-in knowledge base powered by [HackTricks](https://github.com/HackTricks-wiki/hacktricks). When `index_kb` is called without a path, it automatically:

1. **Clones** HackTricks to `~/.sonobat/data/hacktricks/` (first run)
2. **Pulls** latest changes (subsequent runs)
3. **Incrementally indexes** only new/changed files using file mtime comparison

This means `npm install -g sonobat` users get the full knowledge base with a single `index_kb` call — no manual git clone required.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `path` | `~/.sonobat/data/hacktricks/` | Custom path to a HackTricks directory |
| `update` | `true` | Set to `false` to skip git pull before indexing |

The data directory can be overridden with the `SONOBAT_DATA_DIR` environment variable.

## Configuration

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sonobat": {
      "command": "npx",
      "args": ["tsx", "/path/to/sonobat/src/index.ts"],
      "env": {
        "SONOBAT_DB_PATH": "/path/to/sonobat/sonobat.db"
      }
    }
  }
}
```

### Claude Code

Add to `.claude/settings.json`:

```json
{
  "mcpServers": {
    "sonobat": {
      "command": "npx",
      "args": ["tsx", "/path/to/sonobat/src/index.ts"],
      "env": {
        "SONOBAT_DB_PATH": "/path/to/sonobat/sonobat.db"
      }
    }
  }
}
```

### MCP Inspector

```bash
npx @modelcontextprotocol/inspector npx tsx src/index.ts
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SONOBAT_DB_PATH` | `sonobat.db` | Path to the SQLite database file |
| `SONOBAT_DATA_DIR` | `~/.sonobat/data/` | Root data directory for auto-cloned repositories |
| `SONOBAT_ARTIFACT_DIR` | `~/.sonobat/artifacts/` | Allowed root directory for managed artifacts |
| `SONOBAT_ARTIFACT_MAX_BYTES` | `10485760` | Maximum size of one artifact in bytes |

## Tech Stack

| Component | Choice |
|-----------|--------|
| Language | TypeScript 5.x (strict mode) |
| Runtime | Node.js >= 20 LTS |
| Database | SQLite via better-sqlite3 |
| MCP SDK | @modelcontextprotocol/sdk |
| Validation | Zod |
| Build | tsup (esbuild) |
| Test | Vitest |
| Linter | ESLint + @typescript-eslint |
| Formatter | Prettier |

## Development

```bash
npm run dev           # Run with tsx (no build needed)
npm test              # Run all tests
npm run test:watch    # Watch mode
npm run test:coverage # Coverage report
npm run lint          # ESLint
npm run lint:fix      # ESLint with auto-fix
npm run format        # Prettier
npm run format:check  # Prettier check
npm run typecheck     # tsc --noEmit
npm run build         # Production build
```

## License

ISC
