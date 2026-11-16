# Lab 3: Tampered third-party skill (Latitude pattern)

> **Deliberately vulnerable.** Fictional data, simulated tools, local only. Do not deploy.

**Real-world reference:** 2023.  
**Lecture layer:** Layer 3 (supply chain).  
**MAESTRO layers:** L7.

## 1. The lesson

**A third-party skill, reviewed once, can be swapped at any time.**

A 'promo-finder' skill was approved in review. The vendor changed its text after review to include an exfiltration instruction. The agent loads the skill, reads its text, and carries it out. Real-world parallel: Latitude 2023, where a compromise at a service provider led to a large-scale breach.

## 2. Learning outcomes

1. Understand that a skill is prompt text the model will follow
2. Pin each skill by hash and fail closed on change
3. Separate 'approved to use' from 'currently matches what was approved'

## 3. Run it

| Interface | Command |
| --- | --- |
| Browser | `./start.sh` then choose this module in the sidebar |
| Terminal, vulnerable | `python -m au.cli run 3 --mode vulnerable` |
| Terminal, secured | `python -m au.cli run 3 --mode secured` |
| Terminal, your choice | `python -m au.cli run 3 --disable supply_chain,egress` |

Vulnerable mode for this module switches off: `supply_chain`.

## 4. Tasks

Predict the result before each run; then record what you saw.

1. Run Vulnerable mode. Which skill was loaded, and what did it try to do?
2. Run Secured mode. Where in the audit log does the skill get stopped?
3. Edit soc/world.py and change the tampered skill text to match the reviewed description exactly. Does it load now?

## 5. Reflection

1. The egress control was on in Vulnerable mode too. Why does supply_chain still stand alone here?
2. In production, when a skill's hash changes, what should happen operationally?

## 6. Record your finding

```bash
python -m au.cli finding --module 3 --mode vulnerable \
    --attack "What you tried" --result successful --notes "What happened and why"
python -m au.cli export
```

**Maps to:** OWASP LLM03 (supply chain); OWASP MCP; the lecture notes' skills discussion in Chapter 6.. Solutions: [instructor/SOLUTIONS.md](../instructor/SOLUTIONS.md).
