"""Human approval service with action-bound approvals and trusted rendering.

An approval covers one exact action by one agent for one user, and is single-use.
The approval card shown to the human is built by trusted code from the structured
call; any note the agent wrote is labelled untrusted. This is the control the
Qantas-style module teaches, and it cross-links to Module 5 of the SOC lab.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid

# The authorised approvers.
HUMAN_APPROVERS = {"sam.head": "Head of Sales", "ops.lead": "Operations Lead"}
HUMANS = {"jane.rep": "Junior Rep", "ops.pete": "Operations", **HUMAN_APPROVERS}
APPROVAL_TTL_SECONDS = 600


def action_digest(agent: str, tool: str, args: dict, on_behalf_of: str | None) -> str:
    canonical = json.dumps({"agent": agent, "tool": tool, "args": args, "user": on_behalf_of},
                           sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class ApprovalService:
    def __init__(self) -> None:
        self.requests: dict[str, dict] = {}

    def request(self, agent: str, tool: str, args: dict, on_behalf_of: str | None,
                note: str | None = None) -> str:
        rid = "APR-" + uuid.uuid4().hex[:6]
        self.requests[rid] = {
            "id": rid, "agent": agent, "tool": tool, "args": dict(args),
            "on_behalf_of": on_behalf_of, "note": note,
            "digest": action_digest(agent, tool, args, on_behalf_of),
            "decision": None, "approver": None, "used": False,
            "expires": time.time() + APPROVAL_TTL_SECONDS,
        }
        return rid

    def render(self, rid: str, trusted: bool = True) -> str:
        r = self.requests[rid]
        actual = f"{r['agent']} requests {r['tool']}({r['args']}) for user {r['on_behalf_of']}"
        if trusted:
            return actual + (f' | agent note (untrusted): "{r["note"]}"' if r["note"] else "")
        return r["note"] or actual

    def decide(self, rid: str, approver: str, approved: bool, authn: bool = True) -> tuple[bool, str]:
        req = self.requests.get(rid)
        if req is None:
            return False, "unknown approval request"
        if authn and approver not in HUMAN_APPROVERS:
            return False, f"'{approver}' is not an authenticated human approver"
        req["decision"], req["approver"] = approved, approver
        return True, "recorded"

    def consume(self, rid: str, digest: str, binding: bool = True) -> tuple[bool, str]:
        req = self.requests.get(rid)
        if req is None:
            return False, "unknown approval request"
        if req["decision"] is not True:
            return False, "approval not granted"
        if binding:
            if req["digest"] != digest:
                return False, "approval does not match this call"
            if req["used"]:
                return False, "approval already used"
            if time.time() > req["expires"]:
                return False, "approval expired"
        req["used"] = True
        return True, "ok"


def human_would_approve(card: str) -> bool:
    """The scripted Head of Sales. Honest: they approve what the card says,
    and they only approve changes the card describes as 'routine' on a
    customer's own record, or a 'preference' or 'contact' update."""
    text = card.lower()
    if any(w in text for w in ("delete", "export", "bulk", "release_container",
                                "stop_crane", "svc-", "admin", "all_customers")):
        return False
    return any(w in text for w in ("routine", "preference", "contact", "note"))
