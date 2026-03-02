# sonobat

[![CI](https://github.com/0x6d61/sonobat/actions/workflows/ci.yml/badge.svg)](https://github.com/0x6d61/sonobat/actions/workflows/ci.yml)

**AttackDataGraph for autonomous penetration testing.**

sonobat is a graph-native data store that ingests tool outputs (nmap, ffuf, nuclei), builds a structured attack graph using generic `nodes` + `edges` tables, and proposes next-step actions based on missing data. It includes a **HackTricks knowledge base** with FTS5 full-text search and exposes an [MCP Server](https://modelcontextprotocol.io/) so that LLM agents can drive the entire reconnaissance-to-exploitation loop autonomously.

## Features

- **Ingest** — Parse nmap XML, ffuf JSON, and nuclei JSONL into a normalized SQLite graph
- **Graph-Native Schema** — Generic `nodes` + `edges` tables with Zod-validated props for 10 node kinds and 13 edge kinds
- **Propose** — Gap-driven engine suggests what to scan next based on missing data
- **Graph Traversal** — SQLite recursive CTE queries for attack path analysis with preset patterns
- **Knowledge Base** — HackTricks documentation with auto-clone, incremental indexing, and FTS5 full-text search
- **MCP Server** — 6 tools + 4 resources accessible via stdio for LLM agents (Claude Desktop, Claude Code, etc.)

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

edges (kind + source_id + target_id)
 HOST_SERVICE, HOST_VHOST, SERVICE_ENDPOINT, SERVICE_INPUT,
 SERVICE_CREDENTIAL, SERVICE_VULNERABILITY, SERVICE_OBSERVATION,
 ENDPOINT_INPUT, ENDPOINT_VULNERABILITY, ENDPOINT_CREDENTIAL,
 INPUT_OBSERVATION, VULNERABILITY_CVE, VHOST_ENDPOINT
```

Every node can be linked to an **Artifact** (evidence), ensuring full traceability.

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

sonobat runs as an MCP server over stdio. LLM agents connect to it and use tools to ingest data, query the graph, traverse attack paths, and get next-step proposals.

### Available Tools (6)

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
| **`ingest_file`** | Ingest a tool output file (nmap/ffuf/nuclei) and normalize into the graph |
| **`propose`** | Suggest next actions based on missing data in the graph |
| **`search_kb`** | Full-text search the HackTricks knowledge base |
| **`index_kb`** | Auto-clone/pull HackTricks and incrementally index documentation |

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
| Host has no services | `nmap_scan` | Port scan the host |
| HTTP service has no endpoints | `ffuf_discovery` | Directory/file discovery |
| Endpoint has no inputs | `parameter_discovery` | Find input parameters |
| Input has no observations | `value_collection` | Collect parameter values |
| Input has observations but no vulnerabilities | `value_fuzz` | Fuzz the parameter with attack payloads |
| HTTP service has no vhosts | `vhost_discovery` | Virtual host enumeration |
| HTTP service has no vulnerability scan | `nuclei_scan` | Run vulnerability scanner |

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

## Tech Stack

| Component | Choice |
|-----------|--------|
| Language | TypeScript 5.x (strict mode) |
| Runtime | Node.js >= 20 LTS |
| Database | SQLite via better-sqlite3 |
| MCP SDK | @modelcontextprotocol/sdk |
| XML Parser | fast-xml-parser |
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
