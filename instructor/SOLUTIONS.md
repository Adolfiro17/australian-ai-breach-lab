# Instructor Solutions

Attempt each lab first. These are model answers, cross-checked against the code by the test suite where a test exists.

## Lab 1: Over-privileged service account (Optus pattern)

1. Vulnerable: the audit log shows the agent reading customers C-103 (QLD) and C-104 (WA) for jane.rep. Both are outside her NSW territory.
2. Secured: the gateway denies the call with 'user jane.rep (junior_rep, NSW) may not read a record in QLD'.
3. user_authz stands alone; no other control catches it in this module.
4. As sam.head, Secured allows the wide search because her role is ALL territory. The control is scoped per role, not per role-above-this-role.

## Lab 2: Wide tool and no egress wall (Medibank pattern)

1. Vulnerable: run_sql returns four customers; send_email ships them to exfil@evil.example.
2. Secured: the gateway denies run_sql ('general-purpose tool and is not permitted') and denies the external email ('destination is not on the allow-list').
3. With only trust_label off: the directives are followed, but narrow_tool and egress still block the SQL and the external email. Defence in depth.
4. No wording of the planted instruction changes the Secured outcome. Enforcement does not depend on recognising the input.

## Lab 3: Tampered third-party skill (Latitude pattern)

1. Vulnerable: the audit log shows the skill loading (CHANGED since review, loaded anyway), then the agent issuing an http_post.
2. Secured: the gateway quarantines the skill ('content does not match its reviewed hash') and the attack never starts.
3. With the text restored to the reviewed version, the hash matches, the skill loads cleanly, and no instructions trigger.

## Lab 4: Record oversharing (MediSecure pattern)

1. Vulnerable: the Slack channel carries the medicine, the condition_code E11.9 (diabetes) and the raw note.
2. Secured: context_min returns only pickup time, so the model never sees the other fields; redaction strips them too if they did get through.
3. With only redaction off, context_min still limits what the model sees. Each control catches one path.
4. Yes. Redaction is a known-sensitive-field list. A new field needs an entry; otherwise it is fine to leak.

## Lab 5: Destructive action with no HITL (DP World pattern)

1. Vulnerable: release_container on CONT-2001 runs without a valid approver.
2. Secured: the gateway requests approval and ops.pete is not an authorised approver, so the call is rejected.
3. release_container and delete_customer are marked high and irreversible.

## Lab 6: The misleading approval card (Qantas pattern)

1. Vulnerable: the card shows the agent's note about C-101; the Head of Sales approves; the call executes on C-104.
2. Secured: the card is built from the call, so it shows customer_id=C-104 with the agent's note beside it labelled 'untrusted'. The Head of Sales denies it.
3. No wording of the note changes the outcome, because the note is no longer what is approved.
4. The HITL interface itself is a trust boundary. The agent must not write the card.

## Lab 7: Capstone: the fictional 2026 Australian retailer incident

1. Vulnerable: junior rep reads cross-territory; run_sql dumps customers; customer list is emailed externally; a tampered skill loads; health data surfaces in a channel; a container is released without authority; a customer preference is updated on the wrong record.
2. Secured: every attack is denied and the legitimate renewal lookup, prescription pickup, manifest update and C-101 preference refresh all complete.
3. Four controls stand alone in the capstone: user_authz, supply_chain, hitl_binding and approval_display. The rest overlap, so removing any one is survivable with this attack set.
4. Limits: mock model, simulated tools, scripted humans, in-process gateway. Production needs real workload identity, a policy service, secrets manager, and an approval channel the agents cannot write to.

## Lab 8: MAESTRO threat model

1. L1 Foundation Models: the mock model; no control here.
2. L2 Data Operations: context_min, redaction, structured_extract, trust_label — Modules 2 and 4.
3. L3 Agent Frameworks: tool_allowlist, narrow_tool — Modules 2 and 5.
4. L4 Deployment Infrastructure: identity, user_authz, egress — Modules 1 and 2.
5. L5 Evaluation and Observability: audit_integrity; the CI matrix itself.
6. L6 Security and Compliance: hitl_binding, approval_display — Modules 5 and 6.
7. L7 Agent Ecosystem: supply_chain — Module 3.

## Control reference

| Control | Lecture layer | What it does |
| --- | --- | --- |
| `approval_display` | actions | The approval card is built by trusted code from the real call |
| `audit_integrity` | cross-cutting | Append-only, hash-chained audit log |
| `context_minimization` | information | Only the fields the task needs enter the model context |
| `egress` | information | Outbound destinations are checked against an allow-list |
| `hitl_binding` | actions | Human approvals are bound to one exact action and used once |
| `identity` | cross-cutting | Verified workload identity (signed, short-lived token) |
| `narrow_tool` | actions | Tools are narrow and their arguments are validated by the gateway |
| `redaction` | information | Sensitive fields are redacted in model context and in logs |
| `structured_extract` | instructions | External content is extracted to typed fields before the agent reads it |
| `supply_chain` | actions | Skills and MCP tools are hash-pinned and their provenance is verified |
| `tool_allowlist` | actions | Only the tools the agent needs for the task are exposed |
| `trust_label` | instructions | Untrusted content is tagged, and instructions inside it have no authority |
| `user_authz` | information | The agent enforces the user's own permissions, not just a service account's |
