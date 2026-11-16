"""Adolfiro-Australia AI: browser interface for the Australian breach lab.

    streamlit run app.py

Runs entirely offline. The model, the CRM, Slack, Jira and the port tools are
simulators, so no API key or cloud account is needed.
"""
from __future__ import annotations

from pathlib import Path

import streamlit as st

from au import controls as C
from au import findings, maestro
from au.approvals import HUMANS
from au.gateway import ROLE_TOOLS
from au.modules import MODULES, get, run_module
from au.world import PAYLOADS

ROOT = Path(__file__).parent
st.set_page_config(page_title="Adolfiro-Australia AI breach lab", page_icon="🦘", layout="wide")

# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.title("Adolfiro-Australia AI")
    st.caption("An AI security lab framed around recent Australian breaches")
    st.warning("Deliberately vulnerable. Fictional data, simulated tools. Do not deploy.")
    number = st.selectbox("Module", [m.number for m in MODULES],
                          format_func=lambda n: f"{n}. {get(n).title}", key="module")
    spec = get(number)
    st.caption(f"Incident: {spec.incident_year}  ·  Layer: {spec.layer}")

    if spec.slug == "maestro-threat-model":
        st.info("This is an analytical module. There is no Vulnerable/Secured switch.")
        mode = "Secured"
        disabled: set[str] = set()
    else:
        mode = st.radio("Mode", ["Secured", "Vulnerable", "Custom"], key="mode",
                        help="Vulnerable switches off only the controls this module is about.")
        if mode == "Secured":
            disabled = set()
        elif mode == "Vulnerable":
            disabled = set(spec.vulnerable_disables)
        else:
            st.caption("Untick a control to switch it off.")
            disabled = {c for c in sorted(C.ALL)
                        if not st.checkbox(c, value=True, key=f"ctl_{c}", help=C.DESCRIPTIONS[c])}

    human = st.selectbox("You are signed in as", list(HUMANS),
                         format_func=lambda h: f"{h} ({HUMANS[h]})", key="human")
    testing = st.toggle("Security Testing Mode", key="testing",
                        help="Record your own findings and export an assessment.")

# ---------------------------------------------------------------- header
st.header(f"Module {spec.number}: {spec.title}")
st.subheader(spec.lesson)
st.write(spec.story)
off = sorted(disabled)
st.caption("Controls off: " + (", ".join(off) if off else "none (all controls on)"))

payload = None
if spec.payload_key:
    payload = st.text_area(
        "Attacker-controlled content (edit it and re-run)", PAYLOADS[spec.payload_key],
        key=f"payload_{spec.number}", height=120,
        help="The mock model obeys directives written as CALL tool(arg=value).")

run_button_label = "Open the threat model" if spec.slug == "maestro-threat-model" else "Run the scenario"
if st.button(run_button_label, type="primary", key="run"):
    lab, extra = run_module(spec.number, disabled=disabled, payload=payload)
    st.session_state["result"] = {"module": spec.number, "lab": lab, "extra": extra,
                                  "mode": mode.lower()}

res = st.session_state.get("result")
if res and res["module"] != spec.number:
    res = None

tab_labels = ["Verdict", "Agent trace", "Control plane", "Approvals", "Audit log",
              "World state", "Lab guide", "Assessment"]
if spec.slug == "maestro-threat-model":
    tab_labels = ["MAESTRO"] + tab_labels[1:]
tabs = st.tabs(tab_labels)

# ---------------------------------------------------------------- verdict / MAESTRO
with tabs[0]:
    if spec.slug == "maestro-threat-model":
        st.markdown("### Apply MAESTRO to the lab's own architecture")
        st.dataframe(maestro.summary_rows(), use_container_width=True, hide_index=True)
        for L in maestro.LAYERS:
            with st.expander(f"{L['id']} — {L['name']}"):
                st.write(f"**Scope.** {L['scope']}")
                st.write("**Threats.**")
                for t in L["threats"]:
                    st.write(f"- {t}")
                st.write("**In this lab.**")
                for t in L["in_this_lab"]:
                    st.write(f"- {t}")
                if L["modules"]:
                    st.caption("Lab modules: " + ", ".join(str(n) for n in L["modules"]))
                if L["controls"]:
                    st.caption("Controls: " + ", ".join(L["controls"]))
        st.download_button("Export MAESTRO report (Markdown)", maestro.coverage_report(),
                           file_name="maestro.md", mime="text/markdown")
    elif not res:
        st.info("Choose a mode in the sidebar, then run the scenario.")
    else:
        lab, extra = res["lab"], res["extra"]
        damage = lab.damage()
        if damage:
            st.error("ATTACK SUCCEEDED")
            for d in damage:
                st.write(f"- {d}")
        else:
            st.success("ATTACK BLOCKED: no unauthorised effects")
        c1, c2, c3 = st.columns(3)
        c1.metric("Legitimate work completed", "Yes" if extra.get("legit_ok") else "No")
        c2.metric("Calls denied", sum(1 for e in lab.audit.entries if e["outcome"] == "denied"))
        ok, why = lab.audit.verify()
        c3.metric("Audit chain", "Intact" if ok else ("Off" if ok is None else "BROKEN"))
        with st.expander("Extra evidence"):
            st.json({k: v for k, v in extra.items()})

# ---------------------------------------------------------------- agent trace
with tabs[1]:
    if res:
        rows = [{"agent (claimed)": t["agent"], "verified as": t["verified_as"],
                 "on behalf of": t.get("on_behalf_of") or "",
                 "event": t["event"], "outcome": t["outcome"], "detail": t["detail"]}
                for t in res["lab"].trace]
        st.dataframe(rows, use_container_width=True, hide_index=True)
        st.caption("Every tool call passes through the gateway. 'on behalf of' is the end user the agent is acting for.")
    else:
        st.info("Run the scenario to see what the agent did.")

# ---------------------------------------------------------------- control plane
with tabs[2]:
    st.markdown("**Controls** (grouped by the lecture's three layers)")
    st.dataframe([{"layer": C.LAYER[c], "control": c,
                   "state": "OFF" if c in disabled else "on",
                   "what it does": C.DESCRIPTIONS[c]} for c in sorted(C.ALL, key=lambda c: (C.LAYER[c], c))],
                 use_container_width=True, hide_index=True)
    st.markdown("**Role-based tool allow-list**")
    st.dataframe([{"role": r, "allowed tools": ", ".join(t)} for r, t in ROLE_TOOLS.items()],
                 use_container_width=True, hide_index=True)

# ---------------------------------------------------------------- approvals
with tabs[3]:
    if res and res["lab"].approvals.requests:
        st.markdown("**Approval requests in this run**")
        st.dataframe([{"id": r["id"], "requested by": r["agent"],
                       "for user": r["on_behalf_of"] or "",
                       "action": r["tool"], "arguments": str(r["args"]),
                       "agent note": r.get("note") or "",
                       "decision": r["decision"], "approver": r["approver"],
                       "used": r["used"]}
                      for r in res["lab"].approvals.requests.values()],
                     use_container_width=True, hide_index=True)
    else:
        st.info("Run a module that uses human approval (Modules 5 and 6).")

# ---------------------------------------------------------------- audit log
with tabs[4]:
    if res:
        ok, why = res["lab"].audit.verify()
        (st.success if ok else st.warning if ok is None else st.error)(f"Verification: {why}")
        st.dataframe([{"seq": e["seq"], "agent": e["agent"], "on behalf of": e.get("on_behalf_of") or "",
                       "tool": e["tool"], "args": str(e["args"]), "outcome": e["outcome"],
                       "reason": e["reason"], "hash": (e.get("hash") or "")[:12]}
                      for e in res["lab"].audit.entries], use_container_width=True, hide_index=True)
    else:
        st.info("Run the scenario to see the audit log.")

# ---------------------------------------------------------------- world state
with tabs[5]:
    if res:
        w = res["lab"].world
        a, b = st.columns(2)
        a.markdown("**Customers** (CRM)")
        a.dataframe([{"id": k, **v} for k, v in w.customers.items()], hide_index=True)
        a.markdown("**Deals**")
        a.dataframe([{"id": k, **v} for k, v in w.deals.items()], hide_index=True)
        a.markdown("**Prescriptions**")
        a.dataframe([{"id": k, **v} for k, v in w.prescriptions.items()], hide_index=True)
        b.markdown("**Slack (simulated)**")
        b.dataframe(w.slack or [{"text": "none"}], hide_index=True)
        b.markdown("**Outbound requests**")
        b.dataframe(w.outbound or [{"url": "none"}], hide_index=True)
        b.markdown("**Emails**")
        b.dataframe(w.emails or [{"to": "none"}], hide_index=True)
        b.markdown("**Actions taken**")
        b.dataframe(w.actions_taken or [{"action": "none"}], hide_index=True)
    else:
        st.info("Run the scenario to see the simulated world.")

# ---------------------------------------------------------------- lab guide
with tabs[6]:
    guide = ROOT / "labs" / f"{spec.number:02d}-{spec.slug}.md"
    st.markdown(guide.read_text(encoding="utf-8") if guide.exists() else "Handout not found.")

# ---------------------------------------------------------------- assessment
with tabs[7]:
    if not testing:
        st.info("Turn on Security Testing Mode in the sidebar to record findings.")
    else:
        with st.form("finding", clear_on_submit=True):
            attack = st.text_input("What did you try?")
            result = st.selectbox("Your judgement", findings.RESULTS)
            notes = st.text_area("What happened, and why?")
            if st.form_submit_button("Record finding") and attack:
                findings.record(spec.number, mode.lower(), attack, result, notes)
                st.success("Recorded.")
        items = findings.load()
        st.dataframe(items or [{"attack": "no findings yet"}], use_container_width=True, hide_index=True)
        st.download_button("Export assessment (Markdown)", findings.to_markdown(),
                           file_name="au_assessment.md", mime="text/markdown")
        if st.button("Clear my findings", key="clear_findings"):
            findings.clear()
            st.rerun()
