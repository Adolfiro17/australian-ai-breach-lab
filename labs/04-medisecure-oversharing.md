# Lab 4: Record oversharing (MediSecure pattern)

> **Deliberately vulnerable.** Fictional data, simulated tools, local only. Do not deploy.

**Real-world reference:** 2024.  
**Lecture layer:** Layer 1 (information).  
**MAESTRO layers:** L2.

## 1. The lesson

**Context minimisation is a security control, not a performance one.**

A pharmacist asks the agent for a prescription's preferred pickup time. Instead of returning just the pickup time, the whole record enters model context, including the condition code and a free-text note the attacker wrote. The agent's internal summary carries the condition code to a team Slack channel. Real-world parallel: MediSecure 2024, where health records were exposed in a large-scale breach.

## 2. Learning outcomes

1. Apply context minimisation: pass only the fields the task needs
2. Apply redaction of known sensitive fields on retrieval
3. Explain why 'allowed' is not the same as 'should enter model context'

## 3. Run it

| Interface | Command |
| --- | --- |
| Browser | `./start.sh` then choose this module in the sidebar |
| Terminal, vulnerable | `python -m au.cli run 4 --mode vulnerable` |
| Terminal, secured | `python -m au.cli run 4 --mode secured` |
| Terminal, your choice | `python -m au.cli run 4 --disable supply_chain,egress` |

Vulnerable mode for this module switches off: `context_minimization`, `redaction`.

## 4. Tasks

Predict the result before each run; then record what you saw.

1. Run Vulnerable mode. Which health details ended up in the Slack channel?
2. Run Secured mode. Why does the internal summary carry no sensitive data?
3. Switch off only redaction (keep context_min on). Does the sensitive field still surface?
4. Add a new sensitive field ('allergy') to a prescription. Does redaction need updating?

## 5. Reflection

1. Context minimisation is implemented at retrieval. Why is that safer than prompt-engineering it?
2. The lecture argues 'who can access this record' and 'what should enter the model' are different questions. Give an example from your own work.

## 6. Record your finding

```bash
python -m au.cli finding --module 4 --mode vulnerable \
    --attack "What you tried" --result successful --notes "What happened and why"
python -m au.cli export
```

**Maps to:** OWASP LLM02 (sensitive disclosure); the lecture notes' Layer 1 (context minimisation).. Solutions: [instructor/SOLUTIONS.md](../instructor/SOLUTIONS.md).
