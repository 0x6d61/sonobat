# sonobat

**AttackDataGraph for autonomous penetration testing.**

sonobat is a normalized data store that ingests tool outputs (nmap, ffuf, nuclei), builds a structured attack graph, and proposes next-step actions based on missing data. It exposes an [MCP Server](https://modelcontextprotocol.io/) so that LLM agents can drive the entire reconnaissance-to-exploitation loop autonomously.

## Features

- **Ingest** — Parse nmap XML, ffuf JSON, and nuclei JSONL into a normalized SQLite graph
- **Normalize** — Deduplicate and link hosts, services, endpoints, inputs, observations, credentials, and vulnerabilities
- **Propose** — Gap-driven engine suggests what to scan next based on missing data
- **MCP Server** — 14 tools + 3 resources accessible via stdio for LLM agents (Claude Desktop, Claude Code, etc.)

## Data Model

```
Host
 ├── Vhost
 └── Service (transport + port + protocol)
      ├── ServiceObservation (key-value)
      ├── Credential
      ├── HttpEndpoint
      │    └── EndpointInput (many-to-many)
      ├── Input (location + name)
      │    └── Observation (observed values)
      └── Vulnerability
           └── CVE
```

Every fact is linked to an **Artifact** (evidence), ensuring full traceability.

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

sonobat runs as an MCP server over stdio. LLM agents connect to it and use tools to ingest data, query the graph, and get next-step proposals.

### Available Tools

| Category | Tool | Description |
|----------|------|-------------|
| **Ingest** | `ingest_file` | Ingest a tool output file and normalize it into the graph |
| **Query** | `list_hosts` | List all discovered hosts |
| | `get_host` | Get host details including services and vhosts |
| | `list_services` | List services for a host |
| | `list_endpoints` | List HTTP endpoints for a service |
| | `list_inputs` | List input parameters for a service |
| | `list_observations` | List observed values for an input |
| | `list_credentials` | List credentials (optionally filtered by service) |
| | `list_vulnerabilities` | List vulnerabilities (optionally filtered by service/severity) |
| **Propose** | `propose` | Suggest next actions based on missing data |
| **Mutation** | `add_host` | Manually add a host |
| | `add_credential` | Add a credential for a service |
| | `add_vulnerability` | Add a vulnerability for a service |
| | `link_cve` | Link a CVE record to a vulnerability |

### MCP Resources

| URI | Description |
|-----|-------------|
| `sonobat://hosts` | Host list (JSON) |
| `sonobat://hosts/{id}` | Host detail with full service tree |
| `sonobat://summary` | Overall statistics |

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

## Development

```bash
npm run dev           # Run with tsx (no build needed)
npm test              # Run all tests
npm run test:watch    # Watch mode
npm run test:coverage # Coverage report
npm run lint          # ESLint
npm run format        # Prettier
npm run typecheck     # tsc --noEmit
npm run build         # Production build
```

## License

ISC
