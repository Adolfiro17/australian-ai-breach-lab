"""Command-line interface. Same engine as the browser app.

    python -m au.cli list
    python -m au.cli run 3 --mode vulnerable
    python -m au.cli run 2 --disable trust_label,narrow_tool
    python -m au.cli matrix
    python -m au.cli maestro
    python -m au.cli finding --module 3 --mode vulnerable --attack "Tampered skill" --result successful
    python -m au.cli export
"""
from __future__ import annotations

import argparse
import sys

from au import controls as C
from au import findings, maestro
from au.modules import MODULES, get, run_module


def _print_run(key, mode: str, disabled: set | None, payload: str | None) -> bool:
    spec = get(key)
    lab, extra = run_module(spec.number, mode, disabled, payload)
    off = sorted(set(C.ALL) - lab.enabled)
    print(f"\n=== Module {spec.number}: {spec.title} ===")
    print(f"Controls off: {', '.join(off) if off else 'none (Secured)'}\n")
    for t in lab.trace:
        who = t["agent"] if t["agent"] == t["verified_as"] else f"{t['agent']} (really {t['verified_as']})"
        user = f"[user={t['on_behalf_of']}] " if t.get("on_behalf_of") else ""
        print(f"  [{t['outcome']:<16}] {user}{who:<22} {t['event']}")
        if t["outcome"] in ("denied", "pending_approval", "alert") and t["detail"]:
            print(f"  {'':<18} -> {t['detail']}")
    damage = lab.damage()
    print("\nUnauthorised effects:")
    for d in damage or ["none"]:
        print(f"  - {d}")
    print(f"Legitimate work completed: {extra.get('legit_ok')}")
    ok, why = lab.audit.verify()
    print(f"Audit log: {why}")
    print(f"\nVERDICT: {'ATTACK SUCCEEDED' if damage else 'ATTACK BLOCKED'}")
    return bool(damage)


def _matrix() -> int:
    print(f"{'Module':<48}{'Vulnerable':<20}Secured")
    print("-" * 80)
    ok = True
    for m in MODULES:
        if m.slug == "maestro-threat-model":
            print(f" {m.number:>2}. {m.title:<44}{'analytical':<20}analytical")
            continue
        v = bool(run_module(m.number, "vulnerable")[0].damage())
        s_lab, s_extra = run_module(m.number, "secured")
        s = bool(s_lab.damage())
        ok &= v and not s and bool(s_extra.get("legit_ok"))
        print(f" {m.number:>2}. {m.title:<44}"
              f"{'attack succeeds' if v else 'BLOCKED?':<20}{'attack succeeds?' if s else 'blocked'}")
    print("\nRESULT:", "PASS (every attack works when the control is off and is blocked when it is on)"
          if ok else "FAIL")
    return 0 if ok else 1


def _maestro() -> int:
    print(maestro.coverage_report())
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m au.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    r = sub.add_parser("run")
    r.add_argument("module")
    r.add_argument("--mode", choices=["secured", "vulnerable"], default="secured")
    r.add_argument("--disable", default=None)
    r.add_argument("--payload", default=None)
    sub.add_parser("matrix")
    sub.add_parser("maestro")
    sub.add_parser("controls")
    f = sub.add_parser("finding")
    f.add_argument("--module", type=int, required=True)
    f.add_argument("--mode", choices=["secured", "vulnerable", "custom"], default="vulnerable")
    f.add_argument("--attack", required=True)
    f.add_argument("--result", choices=findings.RESULTS, required=True)
    f.add_argument("--notes", default="")
    e = sub.add_parser("export")
    e.add_argument("--out", default="au_assessment.md")
    a = p.parse_args(argv)

    if a.cmd == "list":
        for m in MODULES:
            print(f" {m.number:>2}. [{m.layer}] {m.title}: {m.lesson}")
    elif a.cmd == "controls":
        for c in sorted(C.ALL):
            print(f"{c:<24}[{C.LAYER[c]:<14}] {C.DESCRIPTIONS[c]}")
    elif a.cmd == "run":
        disabled = None
        if a.disable is not None:
            disabled = {c.strip() for c in a.disable.split(",") if c.strip()}
            unknown = disabled - set(C.ALL)
            if unknown:
                print(f"Unknown controls: {sorted(unknown)}")
                return 2
        try:
            numbers = [m.number for m in MODULES] if a.module == "all" else [get(a.module).number]
        except KeyError:
            print(f"No such module: {a.module}")
            return 2
        for n in numbers:
            _print_run(n, a.mode, disabled, a.payload)
    elif a.cmd == "matrix":
        return _matrix()
    elif a.cmd == "maestro":
        return _maestro()
    elif a.cmd == "finding":
        findings.record(a.module, a.mode, a.attack, a.result, a.notes)
        print("Recorded.")
    elif a.cmd == "export":
        print(f"Wrote {findings.export_markdown(a.out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
