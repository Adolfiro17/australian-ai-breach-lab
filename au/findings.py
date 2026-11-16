"""Security Testing Mode: record findings from a lab run and export an
assessment a security lead could read.
"""
from __future__ import annotations

import json
import os
import datetime
from pathlib import Path

RESULTS = ("successful", "blocked", "partial", "inconclusive")


def _file() -> Path:
    return Path(os.environ.get("AU_FINDINGS_FILE", "au_findings.jsonl"))


def record(module: int, mode: str, attack: str, result: str, notes: str = "") -> None:
    if result not in RESULTS:
        raise ValueError(f"result must be one of {RESULTS}")
    row = {"module": module, "mode": mode, "attack": attack, "result": result,
           "notes": notes,
           "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}
    p = _file()
    p.touch(exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


def load() -> list[dict]:
    p = _file()
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def clear() -> None:
    _file().write_text("", encoding="utf-8")


def to_markdown() -> str:
    items = load()
    if not items:
        return "# No findings recorded.\n"
    counts = {r: 0 for r in RESULTS}
    for i in items:
        counts[i["result"]] = counts.get(i["result"], 0) + 1
    lines = ["# Security Assessment: Adolfiro-Australia AI", "",
             "## 1. Summary", "", "| Result | Count |", "| --- | --- |"]
    for r in RESULTS:
        lines.append(f"| {r} | {counts.get(r, 0)} |")
    lines += ["", "## 2. Findings"]
    for i in items:
        lines += ["", f"### Module {i['module']} ({i['mode']}): {i['attack']}",
                  f"- Result: {i['result']}", f"- Recorded: {i['at']}",
                  f"- Notes: {i.get('notes', '') or '(none)'}"]
    return "\n".join(lines) + "\n"


def export_markdown(path="au_assessment.md") -> Path:
    p = Path(path)
    p.write_text(to_markdown(), encoding="utf-8")
    return p
