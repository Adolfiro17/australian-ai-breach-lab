# Lab 8: MAESTRO threat model

> **Deliberately vulnerable.** Fictional data, simulated tools, local only. Do not deploy.

**Real-world reference:** —.  
**Lecture layer:** All seven MAESTRO layers.  
**MAESTRO layers:** L1, L2, L3, L4, L5, L6, L7.

## 1. The lesson

**A layered threat model for agentic AI, applied to the lab's own system.**

An analytical module, not an attack. It walks through the seven MAESTRO layers and maps each to the modules and controls of this lab. Use it as the template you would apply to your own AI systems. The author's own PhD direction extends MAESTRO to name the human-in-the-loop trust boundary explicitly as a distinct failure mode.

## 2. Learning outcomes

1. Explain the seven MAESTRO layers at a level you could teach
2. Map each lab module to the MAESTRO layer(s) it exercises
3. Produce a MAESTRO threat model for one AI system you own or know

## 3. Run it

| Interface | Command |
| --- | --- |
| Browser | `./start.sh` then choose this module in the sidebar |
| Terminal, vulnerable | `python -m au.cli run 8 --mode vulnerable` |
| Terminal, secured | `python -m au.cli run 8 --mode secured` |
| Terminal, your choice | `python -m au.cli run 8 --disable supply_chain,egress` |

Vulnerable mode for this module switches off: none (analytical module).

## 4. Tasks

Predict the result before each run; then record what you saw.

1. Open the MAESTRO reference and read each layer's scope.
2. For every control in the lab, write down which MAESTRO layer it sits in.
3. Pick one AI system you know. Fill in the MAESTRO template from `notes/maestro-reference.md` for it.
4. Export the coverage report and keep it with your findings.

## 5. Reflection

1. MAESTRO is layered. What does a defender gain by thinking in layers instead of as one list?
2. Where does your SOC lab's misleading-approval work sit, and why was the author's PhD direction prompted by it?

## 6. Record your finding

```bash
python -m au.cli finding --module 8 --mode vulnerable \
    --attack "What you tried" --result successful --notes "What happened and why"
python -m au.cli export
```

**Maps to:** MAESTRO; the author's AATM extension (research notes).. Solutions: [instructor/SOLUTIONS.md](../instructor/SOLUTIONS.md).
