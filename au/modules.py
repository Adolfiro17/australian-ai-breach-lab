"""The module registry. Adding a module means adding one ModuleSpec here. The
UI, CLI, tests and handout generator all read from this list.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from au import controls as C
from au import maestro
from au import scenarios as S
from au.lab import Lab


@dataclass
class ModuleSpec:
    number: int
    slug: str
    title: str
    lesson: str
    story: str
    vulnerable_disables: frozenset
    run: Callable[[Lab], dict]
    payload_key: str | None = None
    incident_year: str = ""
    layer: str = ""                      # which lecture layer it stresses
    maestro: list[str] = field(default_factory=list)
    objectives: list[str] = field(default_factory=list)
    tasks: list[str] = field(default_factory=list)
    questions: list[str] = field(default_factory=list)
    solution: list[str] = field(default_factory=list)
    maps_to: str = ""


MODULES: list[ModuleSpec] = [
    ModuleSpec(
        1, "optus-overprivilege", "Over-privileged service account (Optus pattern)",
        "An AI agent inherits its service account's permissions; add natural language and the overreach gets worse.",
        "A junior rep asks the retail AI agent for 'a quick view of our pipeline'. The agent's service "
        "account can read every customer in every territory, so the agent returns records from WA, QLD "
        "and VIC — which the junior rep has no permission to see. Real-world parallel: Optus 2022, where "
        "an unauthenticated API exposed millions of customer records.",
        frozenset({C.USER_AUTHZ}), S.optus_overprivilege, None,
        incident_year="2022", layer="Information",
        maestro=["L4"],
        objectives=[
            "Explain why a service account is not a per-user authorisation story",
            "Enforce the user's permissions on every retrieval",
            "Explain why RBAC/ABAC in the application, not the prompt, is the boundary",
        ],
        tasks=[
            "Run Vulnerable mode as the junior rep. Which records did the agent read?",
            "Run Secured mode. What denial reasons appear in the audit log?",
            "In Custom mode switch off only user_authz and re-run. Which defence catches it instead? (None: this control stands alone.)",
            "Change the acting user to sam.head (Head of Sales, ALL). Does Secured still allow a wide search?",
        ],
        questions=[
            "The Optus breach was a traditional API flaw. Why does an AI agent sitting on top make this worse?",
            "Where in the stack should per-user authorisation be enforced, and why not in the LLM's system prompt?",
        ],
        solution=[
            "Vulnerable: the audit log shows the agent reading customers C-103 (QLD) and C-104 (WA) for jane.rep. "
            "Both are outside her NSW territory.",
            "Secured: the gateway denies the call with 'user jane.rep (junior_rep, NSW) may not read a record in QLD'.",
            "user_authz stands alone; no other control catches it in this module.",
            "As sam.head, Secured allows the wide search because her role is ALL territory. The control is scoped per role, not per role-above-this-role.",
        ],
        maps_to="OWASP LLM01 (indirect) and LLM06 (excessive agency); the lecture notes' Layer 1 (information)."),
    ModuleSpec(
        2, "medibank-wide-tool", "Wide tool and no egress wall (Medibank pattern)",
        "A general-purpose tool plus unrestricted egress is a credential away from bulk exfiltration.",
        "The agent has a run_sql tool for ad-hoc reporting and a send_email tool with no destination "
        "checks. A planted instruction on a competitor page tells it to dump customers and email them "
        "externally. Real-world parallel: Medibank 2022, where stolen credentials led to bulk read and "
        "extortion.",
        frozenset({C.TRUST_LABEL, C.NARROW_TOOL, C.EGRESS}), S.medibank_wide_tool, "competitor_page",
        incident_year="2022", layer="Layers 2 and 3",
        maestro=["L2", "L3"],
        objectives=[
            "Spot a general-purpose tool and replace it with a narrow one",
            "Set an outbound allow-list",
            "Treat retrieved external content as data, not instructions",
        ],
        tasks=[
            "Run Vulnerable mode. Which rows were exfiltrated, and to which address?",
            "Run Secured mode. Why does run_sql fail now, and why does send_email fail?",
            "Switch off only trust_label (keep narrow_tool and egress on). Does the attack still succeed? Why not?",
            "Change the planted instruction on the competitor page. Can you phrase it so the model still carries it out in Secured mode?",
        ],
        questions=[
            "Why is narrow_tool a better fix than a longer prompt instruction to 'only read sales data'?",
            "Egress controls look boring. Why does the lecture put them first?",
        ],
        solution=[
            "Vulnerable: run_sql returns four customers; send_email ships them to exfil@evil.example.",
            "Secured: the gateway denies run_sql ('general-purpose tool and is not permitted') and denies the external email ('destination is not on the allow-list').",
            "With only trust_label off: the directives are followed, but narrow_tool and egress still block the SQL and the external email. Defence in depth.",
            "No wording of the planted instruction changes the Secured outcome. Enforcement does not depend on recognising the input.",
        ],
        maps_to="OWASP LLM01, LLM06, LLM08; the lecture notes' Layer 2 (instructions) and Layer 3 (actions)."),
    ModuleSpec(
        3, "latitude-tampered-skill", "Tampered third-party skill (Latitude pattern)",
        "A third-party skill, reviewed once, can be swapped at any time.",
        "A 'promo-finder' skill was approved in review. The vendor changed its text after review to "
        "include an exfiltration instruction. The agent loads the skill, reads its text, and carries it "
        "out. Real-world parallel: Latitude 2023, where a compromise at a service provider led to a "
        "large-scale breach.",
        frozenset({C.SUPPLY_CHAIN}), S.latitude_supply_chain, "tampered_skill",
        incident_year="2023", layer="Layer 3 (supply chain)",
        maestro=["L7"],
        objectives=[
            "Understand that a skill is prompt text the model will follow",
            "Pin each skill by hash and fail closed on change",
            "Separate 'approved to use' from 'currently matches what was approved'",
        ],
        tasks=[
            "Run Vulnerable mode. Which skill was loaded, and what did it try to do?",
            "Run Secured mode. Where in the audit log does the skill get stopped?",
            "Edit soc/world.py and change the tampered skill text to match the reviewed description exactly. Does it load now?",
        ],
        questions=[
            "The egress control was on in Vulnerable mode too. Why does supply_chain still stand alone here?",
            "In production, when a skill's hash changes, what should happen operationally?",
        ],
        solution=[
            "Vulnerable: the audit log shows the skill loading (CHANGED since review, loaded anyway), then the agent issuing an http_post.",
            "Secured: the gateway quarantines the skill ('content does not match its reviewed hash') and the attack never starts.",
            "With the text restored to the reviewed version, the hash matches, the skill loads cleanly, and no instructions trigger.",
        ],
        maps_to="OWASP LLM03 (supply chain); OWASP MCP; the lecture notes' skills discussion in Chapter 6."),
    ModuleSpec(
        4, "medisecure-oversharing", "Record oversharing (MediSecure pattern)",
        "Context minimisation is a security control, not a performance one.",
        "A pharmacist asks the agent for a prescription's preferred pickup time. Instead of returning "
        "just the pickup time, the whole record enters model context, including the condition code and "
        "a free-text note the attacker wrote. The agent's internal summary carries the condition code "
        "to a team Slack channel. Real-world parallel: MediSecure 2024, where health records were "
        "exposed in a large-scale breach.",
        frozenset({C.CONTEXT_MIN, C.REDACTION}), S.medisecure_oversharing, "prescription_note",
        incident_year="2024", layer="Layer 1 (information)",
        maestro=["L2"],
        objectives=[
            "Apply context minimisation: pass only the fields the task needs",
            "Apply redaction of known sensitive fields on retrieval",
            "Explain why 'allowed' is not the same as 'should enter model context'",
        ],
        tasks=[
            "Run Vulnerable mode. Which health details ended up in the Slack channel?",
            "Run Secured mode. Why does the internal summary carry no sensitive data?",
            "Switch off only redaction (keep context_min on). Does the sensitive field still surface?",
            "Add a new sensitive field ('allergy') to a prescription. Does redaction need updating?",
        ],
        questions=[
            "Context minimisation is implemented at retrieval. Why is that safer than prompt-engineering it?",
            "The lecture argues 'who can access this record' and 'what should enter the model' are different questions. Give an example from your own work.",
        ],
        solution=[
            "Vulnerable: the Slack channel carries the medicine, the condition_code E11.9 (diabetes) and the raw note.",
            "Secured: context_min returns only pickup time, so the model never sees the other fields; redaction strips them too if they did get through.",
            "With only redaction off, context_min still limits what the model sees. Each control catches one path.",
            "Yes. Redaction is a known-sensitive-field list. A new field needs an entry; otherwise it is fine to leak.",
        ],
        maps_to="OWASP LLM02 (sensitive disclosure); the lecture notes' Layer 1 (context minimisation)."),
    ModuleSpec(
        5, "dpworld-destructive-action", "Destructive action with no HITL (DP World pattern)",
        "Irreversible actions must be classified as such and bound to one approved call.",
        "An operations user asks the agent to update a shipping manifest. A planted directive on the "
        "manifest tells the agent to release a container as well — an irreversible, high-impact action. "
        "In Vulnerable mode the agent 'self-approves' and executes. Real-world parallel: DP World 2023, "
        "where a ransomware incident disrupted port operations nationally.",
        frozenset({C.HITL_BINDING}), S.dpworld_destructive_action, None,
        incident_year="2023", layer="Layer 3 (actions)",
        maestro=["L6"],
        objectives=[
            "Classify actions by impact and reversibility",
            "Bind human approvals to one exact action",
            "Keep the manifest update working while blocking the unauthorised release",
        ],
        tasks=[
            "Run Vulnerable mode. Which operational action happened without authority?",
            "Run Secured mode. What does the audit log say about the attempted release?",
            "Look at `au/tools.py`: which tools are marked `high=True` and `irreversible=True`?",
        ],
        questions=[
            "Why is a user's 'approve' not enough on its own?",
            "What does the lecture mean by 'the approval should be tied to the action'?",
        ],
        solution=[
            "Vulnerable: release_container on CONT-2001 runs without a valid approver.",
            "Secured: the gateway requests approval and ops.pete is not an authorised approver, so the call is rejected.",
            "release_container and delete_customer are marked high and irreversible.",
        ],
        maps_to="OWASP LLM06 (excessive agency); the lecture notes' Layer 3 (actions) and Chapter 8 (HITL)."),
    ModuleSpec(
        6, "qantas-misleading-approval", "The misleading approval card (Qantas pattern)",
        "A human can only consent to what they are shown.",
        "Every approval control is on. The approver is authenticated and the approval is bound to one "
        "exact call. The agent writes a note on the approval card saying it is a routine preference "
        "refresh on customer C-101 (Acme Retail Pty). The real call touches C-104, a completely "
        "different customer. Real-world parallel: Qantas 2025, where a third-party call-centre vector "
        "led to a customer data incident. Cross-link: Module 8 of the Secure Agentic SOC Lab.",
        frozenset({C.APPROVAL_DISPLAY}), S.qantas_misleading_approval, "approval_note",
        incident_year="2025", layer="Layer 3 (actions) — HITL trust boundary",
        maestro=["L6"],
        objectives=[
            "Distinguish what was shown to the approver from what was executed",
            "Render the approval card from the structured call, labelling agent text as untrusted",
            "Explain why binding alone does not solve the HITL trust boundary",
        ],
        tasks=[
            "Run Vulnerable mode. Compare the card's note with the actual arguments.",
            "Run Secured mode. What does the card show now, and what did the Head of Sales decide?",
            "Edit the note (the payload) to be as persuasive as you can and run Secured again. Does it matter?",
            "This module cross-references the SOC lab. What is the common pattern?",
        ],
        questions=[
            "Binding was on in Vulnerable mode. Why did it not help?",
            "Besides trusted rendering, what would help a human approver decide well under time pressure?",
        ],
        solution=[
            "Vulnerable: the card shows the agent's note about C-101; the Head of Sales approves; the call executes on C-104.",
            "Secured: the card is built from the call, so it shows customer_id=C-104 with the agent's note beside it labelled 'untrusted'. The Head of Sales denies it.",
            "No wording of the note changes the outcome, because the note is no longer what is approved.",
            "The HITL interface itself is a trust boundary. The agent must not write the card.",
        ],
        maps_to="OWASP LLM06, LLM09; OWASP agentic threats; the lecture notes' Chapter 8 (HITL)."),
    ModuleSpec(
        7, "capstone-retail", "Capstone: the fictional 2026 Australian retailer incident",
        "Every attack at once, and the legitimate retail operation still completes.",
        "A fictional 2026 Australian retailer runs a shopping AI assistant. The incident folds every "
        "earlier attack into one journey: over-privileged reads, a wide tool with no egress wall, a "
        "tampered skill, record oversharing, a destructive port tool, and a misleading approval card. "
        "This is not a report of the real Coles cyber attack; it is a deliberately vulnerable scenario "
        "built around the same classes of pattern.",
        C.ALL, S.capstone_retail_incident, None,
        incident_year="2026 (fictional)", layer="All three",
        maestro=["L2", "L3", "L4", "L6", "L7"],
        objectives=[
            "Trace one retail incident through every layer of the three-layer framework",
            "Find which controls overlap and which stand alone",
            "Produce an assessment a security lead could read",
        ],
        tasks=[
            "Run Vulnerable mode. List every unauthorised effect.",
            "Run Secured mode. Confirm every legitimate workflow still completes.",
            "In Custom mode, switch controls off one at a time. Which single control, when removed, lets an attack through on its own?",
            "Record your findings and export the assessment.",
        ],
        questions=[
            "Which controls overlap, and which stand alone? What does that tell you about where to spend review time?",
            "What does this lab not prove about a production retailer deployment?",
        ],
        solution=[
            "Vulnerable: junior rep reads cross-territory; run_sql dumps customers; customer list is emailed externally; a tampered skill loads; health data surfaces in a channel; a container is released without authority; a customer preference is updated on the wrong record.",
            "Secured: every attack is denied and the legitimate renewal lookup, prescription pickup, manifest update and C-101 preference refresh all complete.",
            "Four controls stand alone in the capstone: user_authz, supply_chain, hitl_binding and approval_display. The rest overlap, so removing any one is survivable with this attack set.",
            "Limits: mock model, simulated tools, scripted humans, in-process gateway. Production needs real workload identity, a policy service, secrets manager, and an approval channel the agents cannot write to.",
        ],
        maps_to="All of the above; the lecture notes' three-layer framework end to end."),
    ModuleSpec(
        8, "maestro-threat-model", "MAESTRO threat model",
        "A layered threat model for agentic AI, applied to the lab's own system.",
        "An analytical module, not an attack. It walks through the seven MAESTRO layers and maps each "
        "to the modules and controls of this lab. Use it as the template you would apply to your own AI "
        "systems. The author's own PhD direction extends MAESTRO to name the human-in-the-loop trust "
        "boundary explicitly as a distinct failure mode.",
        frozenset(), S.maestro_threat_model, None,
        incident_year="—", layer="All seven MAESTRO layers",
        maestro=[L["id"] for L in maestro.LAYERS],
        objectives=[
            "Explain the seven MAESTRO layers at a level you could teach",
            "Map each lab module to the MAESTRO layer(s) it exercises",
            "Produce a MAESTRO threat model for one AI system you own or know",
        ],
        tasks=[
            "Open the MAESTRO reference and read each layer's scope.",
            "For every control in the lab, write down which MAESTRO layer it sits in.",
            "Pick one AI system you know. Fill in the MAESTRO template from `notes/maestro-reference.md` for it.",
            "Export the coverage report and keep it with your findings.",
        ],
        questions=[
            "MAESTRO is layered. What does a defender gain by thinking in layers instead of as one list?",
            "Where does your SOC lab's misleading-approval work sit, and why was the author's PhD direction prompted by it?",
        ],
        solution=[
            "L1 Foundation Models: the mock model; no control here.",
            "L2 Data Operations: context_min, redaction, structured_extract, trust_label — Modules 2 and 4.",
            "L3 Agent Frameworks: tool_allowlist, narrow_tool — Modules 2 and 5.",
            "L4 Deployment Infrastructure: identity, user_authz, egress — Modules 1 and 2.",
            "L5 Evaluation and Observability: audit_integrity; the CI matrix itself.",
            "L6 Security and Compliance: hitl_binding, approval_display — Modules 5 and 6.",
            "L7 Agent Ecosystem: supply_chain — Module 3.",
        ],
        maps_to="MAESTRO; the author's AATM extension (research notes)."),
]


def get(key) -> ModuleSpec:
    for m in MODULES:
        if key in (m.number, m.slug) or str(key) == str(m.number):
            return m
    raise KeyError(f"no such module: {key}")


def run_module(key, mode: str = "secured", disabled: set | None = None,
               payload: str | None = None) -> tuple[Lab, dict]:
    spec = get(key)
    if disabled is None:
        disabled = set(spec.vulnerable_disables) if mode == "vulnerable" else set()
    payloads = {spec.payload_key: payload} if (payload and spec.payload_key) else None
    lab = Lab(disabled=disabled, payloads=payloads)
    extra = spec.run(lab)
    return lab, extra
