# Lab 1: Over-privileged service account (Optus pattern)

> **Deliberately vulnerable.** Fictional data, simulated tools, local only. Do not deploy.

**Real-world reference:** 2022.  
**Lecture layer:** Information.  
**MAESTRO layers:** L4.

## 1. The lesson

**An AI agent inherits its service account's permissions; add natural language and the overreach gets worse.**

A junior rep asks the retail AI agent for 'a quick view of our pipeline'. The agent's service account can read every customer in every territory, so the agent returns records from WA, QLD and VIC — which the junior rep has no permission to see. Real-world parallel: Optus 2022, where an unauthenticated API exposed millions of customer records.

## 2. Learning outcomes

1. Explain why a service account is not a per-user authorisation story
2. Enforce the user's permissions on every retrieval
3. Explain why RBAC/ABAC in the application, not the prompt, is the boundary

## 3. Run it

| Interface | Command |
| --- | --- |
| Browser | `./start.sh` then choose this module in the sidebar |
| Terminal, vulnerable | `python -m au.cli run 1 --mode vulnerable` |
| Terminal, secured | `python -m au.cli run 1 --mode secured` |
| Terminal, your choice | `python -m au.cli run 1 --disable supply_chain,egress` |

Vulnerable mode for this module switches off: `user_authz`.

## 4. Tasks

Predict the result before each run; then record what you saw.

1. Run Vulnerable mode as the junior rep. Which records did the agent read?
2. Run Secured mode. What denial reasons appear in the audit log?
3. In Custom mode switch off only user_authz and re-run. Which defence catches it instead? (None: this control stands alone.)
4. Change the acting user to sam.head (Head of Sales, ALL). Does Secured still allow a wide search?

## 5. Reflection

1. The Optus breach was a traditional API flaw. Why does an AI agent sitting on top make this worse?
2. Where in the stack should per-user authorisation be enforced, and why not in the LLM's system prompt?

## 6. Record your finding

```bash
python -m au.cli finding --module 1 --mode vulnerable \
    --attack "What you tried" --result successful --notes "What happened and why"
python -m au.cli export
```

**Maps to:** OWASP LLM01 (indirect) and LLM06 (excessive agency); the lecture notes' Layer 1 (information).. Solutions: [instructor/SOLUTIONS.md](../instructor/SOLUTIONS.md).
