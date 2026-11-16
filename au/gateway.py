"""The tool gateway for Adolfiro-Australia AI: the independent control plane.

Every tool call from the AI agent passes through here. The checks are grouped
by the lecture's three layers: information, instructions, actions. Nothing
depends on the model behaving well.
"""
from __future__ import annotations

from urllib.parse import urlparse

from au import controls as C
from au.approvals import action_digest
from au.identity import Caller
from au.tools import TOOLS, _territory_of
from au.world import EGRESS_ALLOW_LIST, MCP_PINS, SKILL_PINS

# Allow-list per user role. In Vulnerable mode the tool_allowlist control is off,
# so every tool is exposed.
ROLE_TOOLS = {
    "junior_rep": ["get_customer", "get_deal", "get_renewal_date", "draft_email",
                   "update_customer_preferences"],
    "head_of_sales": ["get_customer", "search_customers", "get_deal", "get_renewal_date",
                      "draft_email", "send_email", "update_customer_preferences",
                      "delete_customer", "http_post"],
    "operations": ["stop_crane", "update_manifest", "release_container"],
    "pharmacist": ["get_prescription", "draft_email", "send_email"],
    "third_party_call_centre": ["get_customer", "draft_email"],
}

# Which role may read which territory, under user_authz.
ROLE_TERRITORY = {
    "junior_rep": "NSW",
    "head_of_sales": "ALL",
    "operations": "VIC",
    "pharmacist": "ALL",
    "third_party_call_centre": "NONE",
}


class ToolGateway:
    def __init__(self, lab) -> None:
        self.lab = lab
        self.calls: dict[str, int] = {}
        self.quarantined: set[str] = set()
        self.loaded_skills: dict[str, str] = {}

    # ------------------------------------------------------------------ helpers
    def _record(self, agent, claimed, on_behalf_of, tool, args, outcome, reason):
        self.lab.audit.append(agent=agent, claimed=claimed, on_behalf_of=on_behalf_of,
                              tool=tool, args=args, outcome=outcome, reason=reason)
        self.lab.trace.append({
            "agent": claimed if claimed != agent else agent,
            "verified_as": agent, "on_behalf_of": on_behalf_of,
            "event": f"{tool}({_short(args)})",
            "outcome": outcome, "detail": reason,
        })

    def _deny(self, agent, claimed, on_behalf_of, tool, args, reason):
        self._record(agent, claimed, on_behalf_of, tool, args, "denied", reason)
        return {"error": f"blocked: {reason}"}

    # ------------------------------------------------------------------ skill supply chain
    def load_skill(self, agent: str, name: str) -> str | None:
        """Layer 3 supply-chain check: a skill's content must match its reviewed pin."""
        text = self.lab.world.skills.get(name)
        if text is None:
            self._record(agent, agent, None, f"skill_load:{name}", {}, "denied", "skill not found")
            return None
        from au.world import _hash
        matches = _hash(text) == SKILL_PINS.get(name)
        if not matches and self.lab.on(C.SUPPLY_CHAIN):
            reason = "skill content does not match its reviewed hash"
            self._record(agent, agent, None, f"skill_load:{name}", {"len": len(text)},
                         "denied", reason)
            self.lab.world.slack.append({"channel": "#sec-alerts",
                                          "text": f"skill {name} quarantined: {reason}"})
            return None
        state = "hash matches the reviewed pin" if matches else "CHANGED since review, loaded anyway (supply_chain off)"
        self._record(agent, agent, None, f"skill_load:{name}", {"len": len(text)}, "allowed", state)
        self.loaded_skills[name] = text
        return text

    # ------------------------------------------------------------------ MCP tools
    def load_mcp_tools(self, agent: str) -> dict[str, str]:
        """Layer 3 supply-chain check for MCP tool descriptions."""
        from au.world import _hash
        loaded = {}
        for name, text in self.lab.world.mcp_manifest.items():
            matches = _hash(text) == MCP_PINS.get(name)
            if not matches and self.lab.on(C.SUPPLY_CHAIN):
                self._record(agent, agent, None, f"mcp_load:{name}", {}, "denied",
                             "MCP tool description changed; quarantined")
                self.quarantined.add(name)
                continue
            self._record(agent, agent, None, f"mcp_load:{name}", {}, "allowed",
                         "pinned description matches review" if matches
                         else "CHANGED since review, loaded anyway (supply_chain off)")
            loaded[name] = text
        return loaded

    # ------------------------------------------------------------------ the boundary
    def call(self, caller: Caller, tool: str, args: dict | None = None,
             approval_id: str | None = None, note: str | None = None):
        lab, args = self.lab, dict(args or {})
        on_behalf_of = caller.on_behalf_of

        # ---- IDENTITY -----------------------------------------------------
        if lab.on(C.IDENTITY):
            agent, why = lab.identity.verify(caller.token)
            if agent is None:
                return self._deny("unauthenticated", caller.claimed_agent, on_behalf_of,
                                   tool, args, f"identity: {why}")
            if caller.claimed_agent != agent:
                return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                                   f"claimed agent '{caller.claimed_agent}' does not match the token")
        else:
            agent = caller.claimed_agent

        spec = TOOLS.get(tool)
        if spec is None:
            return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args, "unknown tool")

        # Audit integrity: no delete through the gateway.
        if tool == "delete_audit" and lab.on(C.AUDIT_INTEGRITY):
            return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                              "audit log is append-only")

        # ---- LAYER 3 (part): tool allow-list -----------------------------
        # A tool must be on the allow-list for the user's role.
        if lab.on(C.TOOL_ALLOWLIST):
            role = None
            if on_behalf_of:
                from au.world import USERS
                user = USERS.get(on_behalf_of)
                role = user["role"] if user else None
            allowed = ROLE_TOOLS.get(role, [])
            if tool not in allowed:
                return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                                   f"'{tool}' is not on the allow-list for user role '{role}'")

        # ---- LAYER 3: narrow-tool enforcement ----------------------------
        # A wide tool (run_sql) is refused when the narrow-tool control is on.
        if lab.on(C.NARROW_TOOL) and spec.get("wide_tool"):
            return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                              f"'{tool}' is a general-purpose tool and is not permitted; use a narrow tool")

        # ---- Required arguments ------------------------------------------
        missing = [k for k in spec["required"] if k not in args]
        if missing:
            return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                              f"missing arguments: {missing}")

        # ---- MCP quarantine ----------------------------------------------
        if tool in self.quarantined:
            return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                              "MCP tool is quarantined: description changed since review")

        # ---- LAYER 1: per-user authorization -----------------------------
        if lab.on(C.USER_AUTHZ):
            # A junior rep may only read deals and customers in their territory.
            if on_behalf_of is None and tool != "http_post":
                return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                                  "tool call carries no on_behalf_of user")
            if on_behalf_of:
                from au.world import USERS
                role = USERS.get(on_behalf_of, {}).get("role")
                user_territory = ROLE_TERRITORY.get(role, "NONE")
                if user_territory == "NONE":
                    return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                                      f"user '{on_behalf_of}' ({role}) has no permission to use '{tool}'")
                if spec.get("wide_read") and user_territory != "ALL":
                    return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                                      f"user '{on_behalf_of}' ({role}) may not perform wide reads")
                record_territory = _territory_of(lab, tool, args)
                if record_territory and user_territory not in ("ALL", record_territory):
                    return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                                      f"user '{on_behalf_of}' ({role}, {user_territory}) "
                                      f"may not read a record in {record_territory}")

        # ---- LAYER 1: egress ---------------------------------------------
        if tool == "http_post" and lab.on(C.EGRESS):
            host = urlparse(str(args.get("url", ""))).hostname or ""
            if host not in EGRESS_ALLOW_LIST:
                return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                                  f"outbound host '{host}' is not on the allow-list")
        if tool == "send_email" and lab.on(C.EGRESS):
            to = str(args.get("to", ""))
            if "@" in to and to.split("@")[1] not in EGRESS_ALLOW_LIST \
               and not to.endswith(".internal"):
                return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                                  f"email destination '{to}' is not on the allow-list")

        # ---- LAYER 3: HITL -----------------------------------------------
        if spec["high"] and lab.on(C.HITL_BINDING):
            digest = action_digest(agent, tool, args, on_behalf_of)
            if approval_id is None:
                rid = lab.approvals.request(agent, tool, args, on_behalf_of, note)
                card = lab.approvals.render(rid, trusted=lab.on(C.APPROVAL_DISPLAY))
                lab.world.slack.append({"channel": "#approvals", "text": f"[{rid}] {card}"})
                self._record(agent, caller.claimed_agent, on_behalf_of, tool, args,
                             "pending_approval", f"high-impact action needs human approval ({rid})")
                return {"error": f"blocked: awaiting human approval ({rid})",
                        "approval_request": rid}
            ok, why = lab.approvals.consume(approval_id, digest, binding=True)
            if not ok:
                return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                                  f"approval rejected: {why}")

        # ---- Execute -----------------------------------------------------
        self.calls[agent] = self.calls.get(agent, 0) + 1
        kwargs = dict(args)
        if spec.get("wants_agent"):
            kwargs["_agent"] = agent
        try:
            result = spec["fn"](lab, **kwargs)
        except TypeError as exc:
            return self._deny(agent, caller.claimed_agent, on_behalf_of, tool, args,
                              f"invalid arguments: {exc}")

        # ---- LAYER 1: context minimisation on the way back --------------
        if spec.get("wide_read") and lab.on(C.CONTEXT_MIN):
            if isinstance(result, dict) and "results" in result:
                result = {"results": [{"id": r.get("id"), "name": r.get("name")} for r in result["results"]]}

        # Record who read what, for the audit tab.
        if on_behalf_of and tool.startswith(("get_", "search_")):
            lab.world.user_reads.append({"user": on_behalf_of, "tool": tool, "args": dict(args)})

        self._record(agent, caller.claimed_agent, on_behalf_of, tool, args,
                     "allowed", "passed all enabled checks")
        return result


def _short(args: dict) -> str:
    text = ", ".join(f"{k}={v}" for k, v in args.items())
    return text if len(text) <= 70 else text[:67] + "..."
