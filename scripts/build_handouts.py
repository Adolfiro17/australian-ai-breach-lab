"""Generate the lab handouts and the instructor solutions from the module
registry. CI runs this and fails if the result drifts from what's committed.

    python scripts/build_handouts.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from au import controls as C  # noqa: E402
from au import maestro  # noqa: E402
from au.modules import MODULES  # noqa: E402


def handout(m) -> str:
    off = ", ".join(f"`{c}`" for c in sorted(m.vulnerable_disables)) if m.vulnerable_disables else "none (analytical module)"
    lines = [
        f"# Lab {m.number}: {m.title}", "",
        "> **Deliberately vulnerable.** Fictional data, simulated tools, local only. Do not deploy.", "",
        f"**Real-world reference:** {m.incident_year}.  ",
        f"**Lecture layer:** {m.layer}.  ",
        f"**MAESTRO layers:** {', '.join(m.maestro) or 'n/a'}.", "",
        "## 1. The lesson", "",
        f"**{m.lesson}**", "",
        m.story, "",
        "## 2. Learning outcomes", "",
        *[f"{i}. {o}" for i, o in enumerate(m.objectives, 1)], "",
        "## 3. Run it", "",
        "| Interface | Command |", "| --- | --- |",
        "| Browser | `./start.sh` then choose this module in the sidebar |",
        f"| Terminal, vulnerable | `python -m au.cli run {m.number} --mode vulnerable` |",
        f"| Terminal, secured | `python -m au.cli run {m.number} --mode secured` |",
        f"| Terminal, your choice | `python -m au.cli run {m.number} --disable supply_chain,egress` |", "",
        f"Vulnerable mode for this module switches off: {off}.", "",
        "## 4. Tasks", "",
        "Predict the result before each run; then record what you saw.", "",
        *[f"{i}. {t}" for i, t in enumerate(m.tasks, 1)], "",
        "## 5. Reflection", "",
        *[f"{i}. {q}" for i, q in enumerate(m.questions, 1)], "",
        "## 6. Record your finding", "", "```bash",
        f'python -m au.cli finding --module {m.number} --mode vulnerable \\',
        '    --attack "What you tried" --result successful --notes "What happened and why"',
        "python -m au.cli export", "```", "",
        f"**Maps to:** {m.maps_to}. Solutions: [instructor/SOLUTIONS.md](../instructor/SOLUTIONS.md).", "",
    ]
    return "\n".join(lines)


def main() -> None:
    (ROOT / "labs").mkdir(exist_ok=True)
    (ROOT / "instructor").mkdir(exist_ok=True)
    for old in (ROOT / "labs").glob("*.md"):
        old.unlink()
    for m in MODULES:
        (ROOT / "labs" / f"{m.number:02d}-{m.slug}.md").write_text(handout(m), encoding="utf-8")
    sol = ["# Instructor Solutions", "",
           "Attempt each lab first. These are model answers, cross-checked against the code by the test suite where a test exists.", ""]
    for m in MODULES:
        sol += [f"## Lab {m.number}: {m.title}", ""]
        for i, s in enumerate(m.solution, 1):
            sol.append(f"{i}. {s}")
        sol.append("")
    sol += ["## Control reference", "",
            "| Control | Lecture layer | What it does |", "| --- | --- | --- |",
            *[f"| `{c}` | {C.LAYER[c]} | {C.DESCRIPTIONS[c]} |" for c in sorted(C.ALL)], ""]
    (ROOT / "instructor" / "SOLUTIONS.md").write_text("\n".join(sol), encoding="utf-8")
    # MAESTRO reference
    (ROOT / "notes").mkdir(exist_ok=True)
    (ROOT / "notes" / "maestro-reference.md").write_text(maestro.coverage_report(), encoding="utf-8")
    print(f"Wrote {len(MODULES)} handouts, instructor/SOLUTIONS.md and notes/maestro-reference.md")


if __name__ == "__main__":
    main()
