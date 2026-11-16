# Lab 2: Wide tool and no egress wall (Medibank pattern)

> **Deliberately vulnerable.** Fictional data, simulated tools, local only. Do not deploy.

**Real-world reference:** 2022.  
**Lecture layer:** Layers 2 and 3.  
**MAESTRO layers:** L2, L3.

## 1. The lesson

**A general-purpose tool plus unrestricted egress is a credential away from bulk exfiltration.**

The agent has a run_sql tool for ad-hoc reporting and a send_email tool with no destination checks. A planted instruction on a competitor page tells it to dump customers and email them externally. Real-world parallel: Medibank 2022, where stolen credentials led to bulk read and extortion.

## 2. Learning outcomes

1. Spot a general-purpose tool and replace it with a narrow one
2. Set an outbound allow-list
3. Treat retrieved external content as data, not instructions

## 3. Run it

| Interface | Command |
| --- | --- |
| Browser | `./start.sh` then choose this module in the sidebar |
| Terminal, vulnerable | `python -m au.cli run 2 --mode vulnerable` |
| Terminal, secured | `python -m au.cli run 2 --mode secured` |
| Terminal, your choice | `python -m au.cli run 2 --disable supply_chain,egress` |

Vulnerable mode for this module switches off: `egress`, `narrow_tool`, `trust_label`.

## 4. Tasks

Predict the result before each run; then record what you saw.

1. Run Vulnerable mode. Which rows were exfiltrated, and to which address?
2. Run Secured mode. Why does run_sql fail now, and why does send_email fail?
3. Switch off only trust_label (keep narrow_tool and egress on). Does the attack still succeed? Why not?
4. Change the planted instruction on the competitor page. Can you phrase it so the model still carries it out in Secured mode?

## 5. Reflection

1. Why is narrow_tool a better fix than a longer prompt instruction to 'only read sales data'?
2. Egress controls look boring. Why does the lecture put them first?

## 6. Record your finding

```bash
python -m au.cli finding --module 2 --mode vulnerable \
    --attack "What you tried" --result successful --notes "What happened and why"
python -m au.cli export
```

**Maps to:** OWASP LLM01, LLM06, LLM08; the lecture notes' Layer 2 (instructions) and Layer 3 (actions).. Solutions: [instructor/SOLUTIONS.md](../instructor/SOLUTIONS.md).
