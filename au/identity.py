"""Workload and user identity.

In the lecture's framework, Layer 1 asks "what information may this agent
retrieve, given who is asking". So the gateway needs both: a verified workload
identity for the agent, and the identity of the human it is acting for.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

AUDIENCE = "retail-gateway"
TTL_SECONDS = 300


@dataclass(frozen=True)
class Caller:
    claimed_agent: str
    token: str
    on_behalf_of: str | None = None       # the human the agent is acting for


class IdentityService:
    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)

    def _sign(self, body: str) -> str:
        return hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()

    def issue(self, agent_id: str, ttl: int = TTL_SECONDS, now: float | None = None) -> str:
        exp = int((time.time() if now is None else now) + ttl)
        body = f"{agent_id}|{AUDIENCE}|{exp}"
        return f"{body}|{self._sign(body)}"

    def verify(self, token: str, now: float | None = None) -> tuple[str | None, str]:
        try:
            agent_id, aud, exp, sig = token.split("|")
        except ValueError:
            return None, "malformed token"
        if not hmac.compare_digest(sig, self._sign(f"{agent_id}|{aud}|{exp}")):
            return None, "bad signature"
        if aud != AUDIENCE:
            return None, "wrong audience"
        if (time.time() if now is None else now) >= int(exp):
            return None, "token expired"
        return agent_id, "ok"
