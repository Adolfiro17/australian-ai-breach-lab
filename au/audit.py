"""Append-only, hash-chained audit log."""
from __future__ import annotations

import hashlib
import json


class AuditLog:
    def __init__(self, chained: bool = True) -> None:
        self.chained = chained
        self.entries: list[dict] = []
        self.deleted = 0
        self._seq = 0

    @staticmethod
    def _hash(prev: str, record: dict) -> str:
        payload = json.dumps(record, sort_keys=True, default=str)
        return hashlib.sha256((prev + payload).encode()).hexdigest()

    def append(self, **record) -> dict:
        self._seq += 1
        record = {"seq": self._seq, **record}
        prev = self.entries[-1]["hash"] if (self.entries and self.chained) else ""
        entry = dict(record)
        if self.chained:
            entry["prev_hash"] = prev
            entry["hash"] = self._hash(prev, record)
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool | None, str]:
        if not self.chained:
            return None, "integrity checking is disabled"
        prev, last_seq = "", 0
        for e in self.entries:
            record = {k: v for k, v in e.items() if k not in ("hash", "prev_hash")}
            if e.get("prev_hash") != prev or e.get("hash") != self._hash(prev, record):
                return False, f"chain broken at seq {e.get('seq')}"
            if e["seq"] != last_seq + 1:
                return False, f"missing record before seq {e['seq']}"
            prev, last_seq = e["hash"], e["seq"]
        return True, f"{len(self.entries)} records, chain intact"
