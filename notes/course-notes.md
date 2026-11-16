# Course Notes: Securing an AI Retail Agent Against Australian Breach Patterns

## 1. The thesis

Most of the recent high-profile Australian breaches were traditional attacks:
unauthenticated APIs, stolen credentials, ransomware and social engineering.
The lab's argument is not that AI makes these attacks happen. It is that an
AI agent connected to the same pipelines inherits, and in several cases
amplifies, exactly the failure modes those breaches exposed, and that the
controls that stop the AI amplification are already named in the three-layer
framework from the lecture notes.

## 2. The three-layer framework, applied

| Layer | Question it answers | Controls here |
| --- | --- | --- |
| Layer 1: Information | What may this agent retrieve, and for whom | `user_authz`, `context_minimization`, `redaction`, `egress` |
| Layer 2: Instructions | What may this agent treat as trustworthy | `trust_label`, `structured_extract` |
| Layer 3: Actions | What may this agent do, and under whose authority | `tool_allowlist`, `narrow_tool`, `supply_chain`, `hitl_binding`, `approval_display` |
| Cross-cutting | Identity and auditability | `identity`, `audit_integrity` |

## 3. Why each Australian breach matters for AI design

### 3.1 Optus (2022) → Module 1

Optus was an API story: a broad permission set behind an endpoint that did not
check the user. An AI agent behind the same endpoint inherits the same breadth
unless the gateway enforces the acting user's permissions on every retrieval.

### 3.2 Medibank (2022) → Module 2

Medibank was a credential story leading to bulk read and extortion. The AI
parallel is a wide tool (SQL) and no egress wall: once an agent is manipulated
into calling the wide tool, it can read everything and send it anywhere.

### 3.3 Latitude Financial (2023) → Module 3

Latitude was a supply-chain story: a service provider's credentials were used
to pivot into the company's systems. In AI terms, the agent's "service
providers" are the skills and MCP tools it loads. A tool whose description or
behaviour has changed since review is the same risk.

### 3.4 MediSecure (2024) → Module 4

MediSecure was about sensitive health data being exposed at scale. For AI, the
analogue is oversharing: a question that only needed one field pulls the whole
record into model context, and the record lands in logs it was never meant to
reach. Context minimisation and redaction are the Layer 1 controls that stop it.

### 3.5 DP World (2023) → Module 5

DP World was a ransomware story that disrupted port operations. For AI, the
analogue is an agent with access to destructive operational tools and no
human-in-the-loop on irreversible actions.

### 3.6 Qantas (2025) → Module 6

Qantas was a social-engineering story against a third-party call centre. The AI
parallel is social engineering of a human approver through the AI's own
summary: the human consents to words that no longer match the call.

### 3.7 The 2026 retail incident (fictional) → Module 7

The capstone is deliberately fictional. It is not a report of any real retail
incident. It is a deliberately vulnerable scenario built around the same
classes of pattern.

## 4. MAESTRO as the second lens

Module 8 applies the MAESTRO framework to the lab's own architecture. The
three-layer lecture framework is the designer's lens; MAESTRO is the reviewer's
lens. Use the first to decide what controls to build, and the second to check
whether you have covered every layer of the system.

## 5. Which controls stand alone

Run the capstone (Module 7) and remove one control at a time. Four controls
stand alone in this attack set: `user_authz`, `supply_chain`, `hitl_binding`
and `approval_display`. The others overlap. That is a defence-in-depth result:
the controls on what is retrieved, what tools are allowed, what is sent out and
what is in context each cover for one another. The controls on who is asking,
what has been checked at review, what a human was shown and what counts as
approval each stand alone.

## 6. A rule for every step

Keep the offline mode as the default and keep `./start.sh matrix` passing. A
real integration is finished only when the same attacks are still blocked with
it switched on.
