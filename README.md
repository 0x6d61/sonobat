# sonobat

[![CI](https://github.com/0x6d61/sonobat/actions/workflows/ci.yml/badge.svg)](https://github.com/0x6d61/sonobat/actions/workflows/ci.yml)

**AttackDataGraph for autonomous penetration testing.**

sonobat is a normalized data store that ingests tool outputs (nmap, ffuf, nuclei), builds a structured attack graph, and proposes next-step actions based on missing data. It includes a built-in **Datalog inference engine** for attack path analysis and exposes an [MCP Server](https://modelcontextprotocol.io/) so that LLM agents can drive the entire reconnaissance-to-exploitation loop autonomously.

## Features

- **Ingest** — Parse nmap XML, ffuf JSON, and nuclei JSONL into a normalized SQLite graph
- **Normalize** — Deduplicate and link hosts, services, endpoints, inputs, observations, credentials, and vulnerabilities
- **Propose** — Gap-driven engine suggests what to scan next based on missing data
- **Datalog Inference** — Built-in Datalog engine for attack path analysis with preset and custom rules
- **MCP Server** — 17 tools + 3 resources accessible via stdio for LLM agents (Claude Desktop, Claude Code, etc.)

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

sonobat runs as an MCP server over stdio. LLM agents connect to it and use tools to ingest data, query the graph, run Datalog inference, and get next-step proposals.

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
| **Datalog** | `list_facts` | Show database contents as Datalog facts |
| | `run_datalog` | Execute a custom Datalog program against the database |
| | `query_attack_paths` | Run preset or saved attack pattern analysis |

### MCP Resources

| URI | Description |
|-----|-------------|
| `sonobat://hosts` | Host list (JSON) |
| `sonobat://hosts/{id}` | Host detail with full service tree |
| `sonobat://summary` | Overall statistics |

## Datalog Inference Engine

sonobat includes a built-in Datalog inference engine that enables attack path analysis by reasoning over the normalized database.

### How It Works

1. **Fact Extraction** — Database rows are automatically converted to Datalog facts (e.g., `host("h-001", "10.0.0.1", "IP")`)
2. **Rule Evaluation** — Naive bottom-up evaluator with fixed-point iteration derives new facts from rules
3. **Query Answering** — Queries return matching tuples with variable bindings

### Available Predicates

| Predicate | Arity | Source Table |
|-----------|-------|-------------|
| `host(Id, Authority, Kind)` | 3 | hosts |
| `service(HostId, Id, Transport, Port, AppProto, State)` | 6 | services |
| `http_endpoint(ServiceId, Id, Method, Path, StatusCode)` | 5 | http_endpoints |
| `input(ServiceId, Id, Location, Name)` | 4 | inputs |
| `endpoint_input(EndpointId, InputId)` | 2 | endpoint_inputs |
| `observation(InputId, Id, RawValue, Source, Confidence)` | 5 | observations |
| `credential(ServiceId, Id, Username, SecretType, Source, Confidence)` | 6 | credentials |
| `vulnerability(ServiceId, Id, VulnType, Title, Severity, Confidence)` | 6 | vulnerabilities |
| `vulnerability_endpoint(VulnId, EndpointId)` | 2 | vulnerabilities |
| `cve(VulnId, CveId, CvssScore)` | 3 | cves |
| `vhost(HostId, Id, Hostname, Source)` | 4 | vhosts |

### Preset Attack Patterns

| Pattern | Description |
|---------|-------------|
| `reachable_services` | Open services reachable on each host |
| `authenticated_access` | Services with known credentials |
| `exploitable_endpoints` | Endpoints with confirmed vulnerabilities |
| `critical_vulns` | Critical and high severity vulnerabilities |
| `attack_surface` | Full attack surface overview |
| `unfuzzed_inputs` | Inputs with observations but no vulnerabilities found yet |

### Custom Rules

LLM agents can write and execute custom Datalog rules via the `run_datalog` MCP tool. Rules can be saved to the database with a `generated_by` field (`human` or `ai`) for future reuse.

```
% Example: Find all HTTP services with SQL injection vulnerabilities
sqli_service(HostId, ServiceId, Title) :-
  service(HostId, ServiceId, "tcp", Port, "http", "open"),
  vulnerability(ServiceId, VulnId, "sqli", Title, Severity, Confidence).
?- sqli_service(HostId, ServiceId, Title).
```

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
