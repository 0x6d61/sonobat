---
name: use-sonobat
description: Use the Sonobat MCP server as external working memory for an authorized penetration test. Read the relevant Assessment before making decisions, preserve raw output as Artifacts, and record confirmed facts, relationships, and investigation history. Sonobat stores state only; the Agent plans and executes the investigation.
---

# Use Sonobat

Treat Sonobat as the shared record for investigation state.
Do not keep material discoveries or evidence references only in chat context.

## Core workflow

1. Use **assessments** to create or select the namespace for the HTB machine or authorized test.
2. Read the current state with **query** and **activities** before relying on prior work.
3. Decide and execute the next investigation yourself.
4. Save large or raw output below `SONOBAT_ARTIFACT_DIR` and register the relative path with **artifacts**.
5. Store confirmed facts with **mutate** and action `upsert_entity`.
6. Connect confirmed facts with **mutate** and action `upsert_relation`.
7. Record what was attempted and what happened with **activities**.
8. Read the updated Assessment before deciding what to investigate next.

## Assessment boundary

Pass `assessmentId` to every graph, Activity, and Artifact operation.
Do not mix Entity, Relation, Activity, or Artifact records between Assessments.
Only use data from the authorized Assessment and its scope.

## Entities and Relations

Use a stable `naturalKey` for each confirmed fact so repeated observations update the same Entity.
Use the migration-defined Entity kinds when applicable:

- `ip_address`
- `host`
- `virtual_host`
- `network_endpoint`
- `service`
- `application`
- `web_endpoint`
- `account`
- `credential`
- `vulnerability`

For a Vhost, use `kind: "virtual_host"` and include `scheme`, `hostname`, and `port` in `properties`.
Include the origin in the natural key, for example `vhost:https://app.example.com:443`.

Represent passwords, hashes, private keys, API keys, tokens, and certificates as `credential`.
Store the subtype in `properties.kind`, the associated principal in `properties.principal`, and the usable value in `properties.value`.
Credential values must not appear in commentary, logs, error messages, filenames, or natural keys.

Use a specific registered Relation kind such as `EXPOSES`, `RUNS`, `ROUTES_TO`, or `AUTHENTICATES_TO` when applicable.
Use `RELATED_TO` only when no more specific relation describes the evidence.

## Activities

Record an Activity for each material investigation attempt.
Use `kind` for the tool or investigation type, `description` for the concrete attempt, and `target` for a non-secret target reference.
When recording the invocation, set `command` to a sanitized command string without credentials or tokens.
Use `completed` or `failed` when the attempt has a result.
Use `started` only when recording an in-progress attempt and do not add `finishedAt`.
Keep `resultSummary` and `errorSummary` concise and free of secret values.

## Artifacts

Write raw output to a file below `SONOBAT_ARTIFACT_DIR` before registering it.
Pass only the path relative to that root.
Use paths such as `activities/<activity-id>/nmap.txt` and never include secrets in filenames.
Register the Artifact with its `assessmentId` and optional `activityId`.

## Reporting

Report the Assessment ID and the IDs of created or changed Activity, Artifact, Entity, and Relation records.
Separate confirmed facts from unverified interpretation.
Do not reproduce Credential values unless the user explicitly asks for them and the request is authorized.

Sonobat does not plan investigations, execute external commands, assign work, manage workers, or store an Agent's chain of thought.
