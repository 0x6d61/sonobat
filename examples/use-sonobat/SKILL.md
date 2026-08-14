---
name: use-sonobat
description: Operate an authorized penetration test through the Sonobat MCP server so an AI Agent consistently reads and updates Engagements, Missions, Actions, the Attack Data Graph, evaluations, and Artifact references. Use whenever an Agent connected to Sonobat plans assessment work, delegates work to a Worker, leases or executes an Action, records tool output, registers discovered targets or Credentials, validates an attack hypothesis, or reports assessment progress.
---

# Use Sonobat

Treat Sonobat as the shared record for assessment state.
Do not keep material plans, discoveries, evidence references, or evaluation results only in chat context.

## Determine the profile

Inspect the available MCP tools before doing assessment work.

- If **engagements**, **missions**, and **actions** are available, follow the tactical workflow.
- If **worker** is available, follow the Worker workflow.
- If neither set is available, stop and request a Sonobat MCP connection.
- Do not emulate operations belonging to the other profile.

The **query**, **mutate**, and **evaluations** tools may exist in both profiles.

## Apply the common rules

Follow these rules in both profiles.

1. Read Sonobat before making a decision that depends on prior work.
2. Write every material discovery or changed conclusion back to Sonobat.
3. Preserve raw tool output as a file and register its relative Artifact path.
4. Link Entity, Relation, and evaluation updates to an Artifact when evidence exists.
5. Never claim that an update succeeded until the MCP call succeeds.
6. Never place a Credential value in commentary, logs, error messages, filenames, or Action descriptions.
7. Use Credential values returned by an authorized query only for the leased and in-scope Action.
8. Do not execute commands outside the Engagement scope or policy.

## Follow the tactical workflow

### Establish the current state

Before creating work:

1. List or retrieve the relevant Engagement.
2. Read its scope and policy.
3. List active Missions for the Engagement.
4. Read the relevant Mission tree, Entity and Relation state, and attack hypotheses.
5. Reuse an existing Mission or Action when it already represents the requested work.

Create an Engagement only when no existing Engagement represents the authorized assessment boundary.

Create a Mission for a tactical objective that requires one or more Actions.
Put the objective, targets, success conditions, and stop conditions in the Mission rather than leaving them only in the Agent prompt.

### Create bounded Actions

Create an Action with:

- one locally executable objective;
- an Action kind that a Worker can advertise;
- the relevant target identifiers in **params**;
- expected results and stop conditions in **params**;
- a stable **dedupeKey**;
- no Credential value in **params**.

Do not perform the Action directly from the tactical profile.
Start or delegate to a Worker through the Agent platform after the Action is queued.
Sonobat does not start the Worker.

### Reassess after Worker updates

After Workers finish or propose more work:

1. Read the Mission tree.
2. Read new or changed Entities, Relations, Artifacts, and attack hypotheses.
3. Adopt a proposed child Action only when it remains within the Mission and is worth its cost.
4. Leave rejected or dismissed high-cost hypotheses recorded with a reason.
5. Create the next Action only after considering the updated state.
6. Complete the Mission only when its success conditions are satisfied.

The number of completed Actions does not determine Mission completion.

## Follow the Worker workflow

### Lease one Action

Call the **worker** tool with action **poll_action** before doing any assessment work.
Pass:

- a stable **workerId**;
- a non-empty list of supported Action kinds;
- a lease duration appropriate for one progress interval.

If no Action is returned, do not invent work.

The response contains the leased Action and its Engagement.
Check the Engagement scope and policy before executing any command or network request.
Reject work that exceeds that boundary.

### Work only on the leased Action

Use the Action objective and **params** as the task boundary.
Query only the Entity, Relation, Credential, evaluation, and prior Artifact data needed for that Action.

Renew the lease before it expires when work is still making progress.
If safe continuation is impossible, finish the Action as failed with a concise error that contains no secret value.

### Save and register evidence

Write raw output below **SONOBAT_ARTIFACT_DIR**.
Use a path that identifies the Action without containing a secret, for example:

~~~text
actions/<action-id>/http-response.txt
~~~

Register only the path relative to **SONOBAT_ARTIFACT_DIR**:

~~~text
actions/<action-id>/http-response.txt
~~~

Do not pass an absolute path.
Register the Artifact before using it as evidence for another record.

### Update the target model

Call the **mutate** tool with action **upsert_entity** for a discovered target or property set.
Use a stable natural key so another Worker updates the same Entity instead of creating a duplicate.

Use these Migration-defined Entity kinds:

- **ip_address**
- **host**
- **virtual_host**
- **network_endpoint**
- **service**
- **application**
- **web_endpoint**
- **account**
- **credential**
- **vulnerability**

Represent passwords, hashes, private keys, API keys, tokens, and certificates as **credential**.
Store the subtype in **properties.kind**, the associated principal in **properties.principal**, and the usable value in **properties.value**.

Call the **mutate** tool with action **upsert_relation** to connect Entities.
Prefer a specific registered Relation kind over **RELATED_TO**.

### Update evaluations

Create an attack hypothesis when the result suggests a plausible route that still requires validation.
Record its objective, preconditions, blockers, and supporting Artifact.

Update the hypothesis after testing it:

- use **validated** when the tested conditions succeeded;
- use **rejected** when evidence disproved it;
- use **dismissed** when it remains possible but its cost is not justified;
- include a reason when dismissing it.

Do not silently discard a high-cost hypothesis.

### Propose additional work

Propose a child Action only when it is necessary to finish or validate the leased parent Action.
The child must remain inside the parent Mission and Engagement.

Do not execute the proposed child Action.
The tactical controller must adopt it first.

### Finish the Action

Before calling the **worker** tool with action **finish_action**:

1. Register every relevant Artifact path.
2. Upsert material Entities and Relations.
3. Record hypothesis validation or dismissal.
4. Propose any necessary child Action.
5. Confirm that all MCP writes succeeded.

Finish as **completed** only when the leased objective has been handled.
Otherwise finish as **failed** with a concise, non-secret error.

## Report to the user

Report the Sonobat records created or changed, including Mission ID, Action ID, Artifact ID, Entity IDs, and hypothesis IDs when applicable.
Separate verified results from untested hypotheses.
Do not reproduce Credential values in the report unless the user explicitly asks for them.
