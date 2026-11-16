"""MAESTRO threat model for Module 8.

MAESTRO (Multi-Agent Environment, Security, Threat, Risk and Outcome) is a
threat-modelling framework for agentic AI systems, with seven layers. This
module applies it to Adolfiro-Australia AI's own architecture and cross-links
each layer to the modules that exercise its threats.
"""
from __future__ import annotations

from au import controls as C

LAYERS = [
    {
        "id": "L1", "name": "Foundation Models",
        "scope": "The underlying LLM: its training, weights and prompt interface.",
        "threats": [
            "Backdoored or biased base model",
            "Model-serving API compromise",
            "Jailbreak prompts that override system instructions",
        ],
        "in_this_lab": [
            "The mock model is fully manipulable on purpose, so every attack lands here first.",
            "Controls at this layer alone cannot stop the attacks; they live elsewhere.",
        ],
        "modules": [1, 2, 4],
        "controls": [],
    },
    {
        "id": "L2", "name": "Data Operations",
        "scope": "Retrieval, context assembly, embeddings and the data fed to the model.",
        "threats": [
            "Indirect prompt injection in retrieved content",
            "Oversharing: whole records returned when one field was asked",
            "Sensitive fields left in model context and logs",
        ],
        "in_this_lab": [
            "Competitor page (Module 2) and prescription notes (Module 4) carry planted instructions.",
            "The whole prescription record enters context in Module 4 when context minimisation is off.",
        ],
        "modules": [2, 4],
        "controls": [C.CONTEXT_MIN, C.REDACTION, C.STRUCTURED_EXTRACT, C.TRUST_LABEL],
    },
    {
        "id": "L3", "name": "Agent Frameworks",
        "scope": "The orchestration layer: tool definitions, agent memory, inter-agent calls.",
        "threats": [
            "Over-wide tool access and excessive agency",
            "General-purpose tools (SQL, shell) when a narrow tool would do",
            "Confused deputy between agents",
        ],
        "in_this_lab": [
            "A general-purpose SQL tool in Module 2 and a destructive port tool in Module 5.",
            "The tool allow-list and narrow-tool controls live at this layer.",
        ],
        "modules": [2, 5],
        "controls": [C.TOOL_ALLOWLIST, C.NARROW_TOOL],
    },
    {
        "id": "L4", "name": "Deployment Infrastructure",
        "scope": "Where the agent runs: workload identity, network boundaries, secrets.",
        "threats": [
            "Over-privileged service accounts (the Optus pattern)",
            "No per-user authorisation on top of the agent's service identity",
            "Flat network with no egress controls",
        ],
        "in_this_lab": [
            "A junior rep's query reads records across territories when user_authz is off (Module 1).",
            "Outbound HTTP and email are stopped at the egress layer.",
        ],
        "modules": [1, 2],
        "controls": [C.IDENTITY, C.USER_AUTHZ, C.EGRESS],
    },
    {
        "id": "L5", "name": "Evaluation and Observability",
        "scope": "Red teaming, security evals, audit logs and monitoring.",
        "threats": [
            "No tamper-evident log of agent actions",
            "No regression tests for security controls",
            "Red-team findings never fed back into CI",
        ],
        "in_this_lab": [
            "Hash-chained audit log; every denial is recorded as evidence.",
            "`./start.sh matrix` runs every attack in both modes as part of CI.",
        ],
        "modules": [],
        "controls": [C.AUDIT_INTEGRITY],
    },
    {
        "id": "L6", "name": "Security and Compliance",
        "scope": "Human oversight, approvals and policy enforcement at the trust boundary.",
        "threats": [
            "An agent that approves its own actions",
            "Approval replay and target swap",
            "An AI-written approval card that the approver cannot verify",
        ],
        "in_this_lab": [
            "Module 5: no HITL on an irreversible action.",
            "Module 6: the approval card is written by the agent (misleading approval).",
            "Cross-link: Modules 5-7 of the Secure Agentic SOC Lab cover the HITL family in depth.",
        ],
        "modules": [5, 6],
        "controls": [C.HITL_BINDING, C.APPROVAL_DISPLAY],
    },
    {
        "id": "L7", "name": "Agent Ecosystem",
        "scope": "Skills, MCP servers and third-party integrations the agent consumes.",
        "threats": [
            "Tampered skill after review (rug-pull)",
            "MCP tool description changed since review",
            "Untrusted third-party agent in a multi-agent workflow",
        ],
        "in_this_lab": [
            "Module 3: a third-party skill tampered after review.",
            "Supply-chain control pins each skill and MCP tool description by hash.",
        ],
        "modules": [3],
        "controls": [C.SUPPLY_CHAIN],
    },
]


def layers_for_module(number: int) -> list[str]:
    """Return the MAESTRO layer ids that a module exercises."""
    return [L["id"] for L in LAYERS if number in L["modules"]]


def summary_rows() -> list[dict]:
    rows = []
    for L in LAYERS:
        rows.append({
            "layer": f"{L['id']} {L['name']}",
            "scope": L["scope"],
            "controls": ", ".join(L["controls"]) or "n/a",
            "modules": ", ".join(str(m) for m in L["modules"]) or "n/a",
        })
    return rows


def coverage_report() -> str:
    """A Markdown report applying MAESTRO to the lab."""
    lines = ["# MAESTRO threat model: Adolfiro-Australia AI", "",
             "This is Module 8 of the Australian breach lab. It applies the MAESTRO",
             "framework to the lab's own architecture and cross-references each layer",
             "to the modules that exercise its threats and the controls that mitigate them.",
             "",
             "## 1. Layers at a glance",
             "",
             "| Layer | Scope | Lab modules | Controls |",
             "| --- | --- | --- | --- |"]
    for L in LAYERS:
        modules = ", ".join(str(m) for m in L["modules"]) or "n/a"
        ctrls = ", ".join(f"`{c}`" for c in L["controls"]) or "n/a"
        lines.append(f"| **{L['id']} {L['name']}** | {L['scope']} | {modules} | {ctrls} |")
    lines.append("")
    for L in LAYERS:
        lines.append(f"## 2. {L['id']} {L['name']}")
        lines.append("")
        lines.append(f"**Scope.** {L['scope']}")
        lines.append("")
        lines.append("**Threats.**")
        for t in L["threats"]:
            lines.append(f"- {t}")
        lines.append("")
        lines.append("**In this lab.**")
        for t in L["in_this_lab"]:
            lines.append(f"- {t}")
        lines.append("")
    lines.append("## 3. How to use this layered view")
    lines.append("")
    lines.append("1. For each AI system you design, start from L1 and walk down. For each layer,")
    lines.append("   write one threat that applies to your system and name the control that mitigates it.")
    lines.append("2. Mark which threats you have a working test for. Untested controls are not controls.")
    lines.append("3. Where a threat has no mapped control, add one or accept the risk explicitly.")
    lines.append("4. In production, the MAESTRO layers map to different teams: data engineering (L2),")
    lines.append("   platform (L4), security (L6), SRE (L5). Use the mapping to assign ownership.")
    return "\n".join(lines)
