# Lab 7: Capstone: the fictional 2026 Australian retailer incident

> **Deliberately vulnerable.** Fictional data, simulated tools, local only. Do not deploy.

**Real-world reference:** 2026 (fictional).  
**Lecture layer:** All three.  
**MAESTRO layers:** L2, L3, L4, L6, L7.

## 1. The lesson

**Every attack at once, and the legitimate retail operation still completes.**

A fictional 2026 Australian retailer runs a shopping AI assistant. The incident folds every earlier attack into one journey: over-privileged reads, a wide tool with no egress wall, a tampered skill, record oversharing, a destructive port tool, and a misleading approval card. This is not a report of the real Coles cyber attack; it is a deliberately vulnerable scenario built around the same classes of pattern.

## 2. Learning outcomes

1. Trace one retail incident through every layer of the three-layer framework
2. Find which controls overlap and which stand alone
3. Produce an assessment a security lead could read

## 3. Run it

| Interface | Command |
| --- | --- |
| Browser | `./start.sh` then choose this module in the sidebar |
| Terminal, vulnerable | `python -m au.cli run 7 --mode vulnerable` |
| Terminal, secured | `python -m au.cli run 7 --mode secured` |
| Terminal, your choice | `python -m au.cli run 7 --disable supply_chain,egress` |

Vulnerable mode for this module switches off: `approval_display`, `audit_integrity`, `context_minimization`, `egress`, `hitl_binding`, `identity`, `narrow_tool`, `redaction`, `structured_extract`, `supply_chain`, `tool_allowlist`, `trust_label`, `user_authz`.

## 4. Tasks

Predict the result before each run; then record what you saw.

1. Run Vulnerable mode. List every unauthorised effect.
2. Run Secured mode. Confirm every legitimate workflow still completes.
3. In Custom mode, switch controls off one at a time. Which single control, when removed, lets an attack through on its own?
4. Record your findings and export the assessment.

## 5. Reflection

1. Which controls overlap, and which stand alone? What does that tell you about where to spend review time?
2. What does this lab not prove about a production retailer deployment?

## 6. Record your finding

```bash
python -m au.cli finding --module 7 --mode vulnerable \
    --attack "What you tried" --result successful --notes "What happened and why"
python -m au.cli export
```

**Maps to:** All of the above; the lecture notes' three-layer framework end to end.. Solutions: [instructor/SOLUTIONS.md](../instructor/SOLUTIONS.md).
