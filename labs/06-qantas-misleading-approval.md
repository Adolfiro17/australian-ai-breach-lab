# Lab 6: The misleading approval card (Qantas pattern)

> **Deliberately vulnerable.** Fictional data, simulated tools, local only. Do not deploy.

**Real-world reference:** 2025.  
**Lecture layer:** Layer 3 (actions) — HITL trust boundary.  
**MAESTRO layers:** L6.

## 1. The lesson

**A human can only consent to what they are shown.**

Every approval control is on. The approver is authenticated and the approval is bound to one exact call. The agent writes a note on the approval card saying it is a routine preference refresh on customer C-101 (Acme Retail Pty). The real call touches C-104, a completely different customer. Real-world parallel: Qantas 2025, where a third-party call-centre vector led to a customer data incident. Cross-link: Module 8 of the Secure Agentic SOC Lab.

## 2. Learning outcomes

1. Distinguish what was shown to the approver from what was executed
2. Render the approval card from the structured call, labelling agent text as untrusted
3. Explain why binding alone does not solve the HITL trust boundary

## 3. Run it

| Interface | Command |
| --- | --- |
| Browser | `./start.sh` then choose this module in the sidebar |
| Terminal, vulnerable | `python -m au.cli run 6 --mode vulnerable` |
| Terminal, secured | `python -m au.cli run 6 --mode secured` |
| Terminal, your choice | `python -m au.cli run 6 --disable supply_chain,egress` |

Vulnerable mode for this module switches off: `approval_display`.

## 4. Tasks

Predict the result before each run; then record what you saw.

1. Run Vulnerable mode. Compare the card's note with the actual arguments.
2. Run Secured mode. What does the card show now, and what did the Head of Sales decide?
3. Edit the note (the payload) to be as persuasive as you can and run Secured again. Does it matter?
4. This module cross-references the SOC lab. What is the common pattern?

## 5. Reflection

1. Binding was on in Vulnerable mode. Why did it not help?
2. Besides trusted rendering, what would help a human approver decide well under time pressure?

## 6. Record your finding

```bash
python -m au.cli finding --module 6 --mode vulnerable \
    --attack "What you tried" --result successful --notes "What happened and why"
python -m au.cli export
```

**Maps to:** OWASP LLM06, LLM09; OWASP agentic threats; the lecture notes' Chapter 8 (HITL).. Solutions: [instructor/SOLUTIONS.md](../instructor/SOLUTIONS.md).
