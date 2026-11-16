"""The security controls the Australian breach lab can switch on and off.

The controls are grouped by the lecture's three layers: information, instructions
and actions, plus cross-cutting services. In Secured mode every control is on.
Each module's Vulnerable mode switches off only the controls that module is
about, so the other controls keep working and you can see defence in depth.
"""
from __future__ import annotations

# Layer 1: information
USER_AUTHZ = "user_authz"                      # the agent enforces the user's own permissions
CONTEXT_MIN = "context_minimization"           # only the fields the task needs enter the model
REDACTION = "redaction"                        # sensitive fields are redacted in model context and logs
EGRESS = "egress"                              # outbound destinations are allow-listed

# Layer 2: instructions
TRUST_LABEL = "trust_label"                    # untrusted content is tagged and never re-authorised
STRUCTURED_EXTRACT = "structured_extract"      # external content is extracted to typed fields

# Layer 3: actions
TOOL_ALLOWLIST = "tool_allowlist"              # only the tools the agent needs are exposed
NARROW_TOOL = "narrow_tool"                    # tools are narrow and parameter-validated
SUPPLY_CHAIN = "supply_chain"                  # skills and tools are hash-pinned and provenance-checked
HITL_BINDING = "hitl_binding"                  # approvals are bound to one exact action, single use
APPROVAL_DISPLAY = "approval_display"          # approval card is built by trusted code

# Cross-cutting
IDENTITY = "identity"                          # verified workload identity
AUDIT_INTEGRITY = "audit_integrity"            # append-only, hash-chained audit log


ALL = frozenset({USER_AUTHZ, CONTEXT_MIN, REDACTION, EGRESS,
                 TRUST_LABEL, STRUCTURED_EXTRACT,
                 TOOL_ALLOWLIST, NARROW_TOOL, SUPPLY_CHAIN, HITL_BINDING, APPROVAL_DISPLAY,
                 IDENTITY, AUDIT_INTEGRITY})

LAYER = {
    USER_AUTHZ: "information", CONTEXT_MIN: "information",
    REDACTION: "information", EGRESS: "information",
    TRUST_LABEL: "instructions", STRUCTURED_EXTRACT: "instructions",
    TOOL_ALLOWLIST: "actions", NARROW_TOOL: "actions", SUPPLY_CHAIN: "actions",
    HITL_BINDING: "actions", APPROVAL_DISPLAY: "actions",
    IDENTITY: "cross-cutting", AUDIT_INTEGRITY: "cross-cutting",
}

DESCRIPTIONS = {
    USER_AUTHZ: "The agent enforces the user's own permissions, not just a service account's",
    CONTEXT_MIN: "Only the fields the task needs enter the model context",
    REDACTION: "Sensitive fields are redacted in model context and in logs",
    EGRESS: "Outbound destinations are checked against an allow-list",
    TRUST_LABEL: "Untrusted content is tagged, and instructions inside it have no authority",
    STRUCTURED_EXTRACT: "External content is extracted to typed fields before the agent reads it",
    TOOL_ALLOWLIST: "Only the tools the agent needs for the task are exposed",
    NARROW_TOOL: "Tools are narrow and their arguments are validated by the gateway",
    SUPPLY_CHAIN: "Skills and MCP tools are hash-pinned and their provenance is verified",
    HITL_BINDING: "Human approvals are bound to one exact action and used once",
    APPROVAL_DISPLAY: "The approval card is built by trusted code from the real call",
    IDENTITY: "Verified workload identity (signed, short-lived token)",
    AUDIT_INTEGRITY: "Append-only, hash-chained audit log",
}
