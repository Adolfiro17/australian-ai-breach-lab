# MAESTRO threat model: Adolfiro-Australia AI

This is Module 8 of the Australian breach lab. It applies the MAESTRO
framework to the lab's own architecture and cross-references each layer
to the modules that exercise its threats and the controls that mitigate them.

## 1. Layers at a glance

| Layer | Scope | Lab modules | Controls |
| --- | --- | --- | --- |
| **L1 Foundation Models** | The underlying LLM: its training, weights and prompt interface. | 1, 2, 4 | n/a |
| **L2 Data Operations** | Retrieval, context assembly, embeddings and the data fed to the model. | 2, 4 | `context_minimization`, `redaction`, `structured_extract`, `trust_label` |
| **L3 Agent Frameworks** | The orchestration layer: tool definitions, agent memory, inter-agent calls. | 2, 5 | `tool_allowlist`, `narrow_tool` |
| **L4 Deployment Infrastructure** | Where the agent runs: workload identity, network boundaries, secrets. | 1, 2 | `identity`, `user_authz`, `egress` |
| **L5 Evaluation and Observability** | Red teaming, security evals, audit logs and monitoring. | n/a | `audit_integrity` |
| **L6 Security and Compliance** | Human oversight, approvals and policy enforcement at the trust boundary. | 5, 6 | `hitl_binding`, `approval_display` |
| **L7 Agent Ecosystem** | Skills, MCP servers and third-party integrations the agent consumes. | 3 | `supply_chain` |

## 2. L1 Foundation Models

**Scope.** The underlying LLM: its training, weights and prompt interface.

**Threats.**
- Backdoored or biased base model
- Model-serving API compromise
- Jailbreak prompts that override system instructions

**In this lab.**
- The mock model is fully manipulable on purpose, so every attack lands here first.
- Controls at this layer alone cannot stop the attacks; they live elsewhere.

## 2. L2 Data Operations

**Scope.** Retrieval, context assembly, embeddings and the data fed to the model.

**Threats.**
- Indirect prompt injection in retrieved content
- Oversharing: whole records returned when one field was asked
- Sensitive fields left in model context and logs

**In this lab.**
- Competitor page (Module 2) and prescription notes (Module 4) carry planted instructions.
- The whole prescription record enters context in Module 4 when context minimisation is off.

## 2. L3 Agent Frameworks

**Scope.** The orchestration layer: tool definitions, agent memory, inter-agent calls.

**Threats.**
- Over-wide tool access and excessive agency
- General-purpose tools (SQL, shell) when a narrow tool would do
- Confused deputy between agents

**In this lab.**
- A general-purpose SQL tool in Module 2 and a destructive port tool in Module 5.
- The tool allow-list and narrow-tool controls live at this layer.

## 2. L4 Deployment Infrastructure

**Scope.** Where the agent runs: workload identity, network boundaries, secrets.

**Threats.**
- Over-privileged service accounts (the Optus pattern)
- No per-user authorisation on top of the agent's service identity
- Flat network with no egress controls

**In this lab.**
- A junior rep's query reads records across territories when user_authz is off (Module 1).
- Outbound HTTP and email are stopped at the egress layer.

## 2. L5 Evaluation and Observability

**Scope.** Red teaming, security evals, audit logs and monitoring.

**Threats.**
- No tamper-evident log of agent actions
- No regression tests for security controls
- Red-team findings never fed back into CI

**In this lab.**
- Hash-chained audit log; every denial is recorded as evidence.
- `./start.sh matrix` runs every attack in both modes as part of CI.

## 2. L6 Security and Compliance

**Scope.** Human oversight, approvals and policy enforcement at the trust boundary.

**Threats.**
- An agent that approves its own actions
- Approval replay and target swap
- An AI-written approval card that the approver cannot verify

**In this lab.**
- Module 5: no HITL on an irreversible action.
- Module 6: the approval card is written by the agent (misleading approval).
- Cross-link: Modules 5-7 of the Secure Agentic SOC Lab cover the HITL family in depth.

## 2. L7 Agent Ecosystem

**Scope.** Skills, MCP servers and third-party integrations the agent consumes.

**Threats.**
- Tampered skill after review (rug-pull)
- MCP tool description changed since review
- Untrusted third-party agent in a multi-agent workflow

**In this lab.**
- Module 3: a third-party skill tampered after review.
- Supply-chain control pins each skill and MCP tool description by hash.

## 3. How to use this layered view

1. For each AI system you design, start from L1 and walk down. For each layer,
   write one threat that applies to your system and name the control that mitigates it.
2. Mark which threats you have a working test for. Untested controls are not controls.
3. Where a threat has no mapped control, add one or accept the risk explicitly.
4. In production, the MAESTRO layers map to different teams: data engineering (L2),
   platform (L4), security (L6), SRE (L5). Use the mapping to assign ownership.