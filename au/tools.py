"""Simulated tools the retail AI agent can call.

The deliberately wide tools (run_sql, send_email) demonstrate what happens when
Layer 3 (actions) is missing. The narrow ones (get_customer, draft_email) show
the fix. Each tool is marked with its impact class.
"""
from __future__ import annotations

from urllib.parse import urlparse

from au import controls as C

# Fields treated as sensitive. The gateway's redaction control strips these.
SENSITIVE_FIELDS = ("medicare", "phone", "notes", "condition_code")


# -- information tools ----------------------------------------------------
def get_customer(lab, customer_id: str):
    rec = lab.world.customers.get(customer_id)
    if rec is None:
        return {"error": f"no such customer: {customer_id}"}
    return _project(dict(rec, id=customer_id), lab)


def search_customers(lab, query: str = "*"):
    rows = [dict(r, id=k) for k, r in lab.world.customers.items()]
    if query != "*":
        q = query.lower()
        rows = [r for r in rows if q in r["name"].lower()]
    return {"results": [_project(r, lab) for r in rows]}


def get_deal(lab, deal_id: str):
    rec = lab.world.deals.get(deal_id)
    if rec is None:
        return {"error": f"no such deal: {deal_id}"}
    return dict(rec, id=deal_id)


def get_prescription(lab, rx_id: str):
    rec = lab.world.prescriptions.get(rx_id)
    if rec is None:
        return {"error": f"no such prescription: {rx_id}"}
    record = dict(rec, id=rx_id)
    if lab.on(C.CONTEXT_MIN):
        # Context minimisation: for a pickup-time question, project to the fields
        # needed. The condition code and the free-text note stay out of context.
        record = {k: v for k, v in record.items() if k in ("id", "patient", "medicine", "dose")}
    return _project(record, lab)


def get_renewal_date(lab, deal_id: str):
    """A narrow version of get_deal: the Layer 1 fix in the MediSecure/MediScript
    module. It returns only the renewal date, not the whole record."""
    rec = lab.world.deals.get(deal_id)
    if rec is None:
        return {"error": f"no such deal: {deal_id}"}
    return {"deal_id": deal_id, "renewal": rec["renewal"]}


# -- wide, dangerous tools ------------------------------------------------
def run_sql(lab, statement: str):
    """A deliberately wide tool. In Secured mode it is not on the allow-list,
    so the gateway denies it."""
    table_data = {
        "customers": list(lab.world.customers.values()),
        "deals": list(lab.world.deals.values()),
        "prescriptions": list(lab.world.prescriptions.values()),
    }
    lowered = statement.lower()
    for table, rows in table_data.items():
        if table in lowered:
            return {"rows": rows}
    return {"rows": []}


def send_email(lab, to: str, subject: str, body: str):
    """A wide send_email. Narrow version is draft_email."""
    lab.world.emails.append({"to": to, "subject": subject, "body": body})
    lab.world.outbound.append({"url": f"mailto:{to}", "host": to.split("@")[-1] if "@" in to else "",
                                "body": body})
    return {"sent": to}


def draft_email(lab, to: str, subject: str, body: str, _agent: str = "?"):
    """A narrower version: drafts stay in Drafts until a human sends them."""
    lab.world.emails.append({"to": to, "subject": subject, "body": body,
                             "status": "drafted", "by": _agent})
    return {"drafted": to}


# -- egress ----------------------------------------------------------------
def http_post(lab, url: str, body: str = ""):
    lab.world.outbound.append({"url": url, "host": urlparse(url).hostname or "", "body": str(body)})
    return {"status": 200}


# -- retail / port operational actions -----------------------------------
def stop_crane(lab, crane_id: str, _agent: str = "?"):
    lab.world.actions_taken.append({"action": "stop_crane", "target": crane_id, "by": _agent})
    return {"stopped": crane_id}


def release_container(lab, container_id: str, _agent: str = "?"):
    lab.world.actions_taken.append({"action": "release_container", "target": container_id, "by": _agent})
    return {"released": container_id}


def update_manifest(lab, manifest_id: str, field: str, value: str, _agent: str = "?"):
    lab.world.actions_taken.append({"action": "update_manifest", "target": manifest_id,
                                     "field": field, "value": value, "by": _agent})
    return {"updated": manifest_id}


# -- customer record actions ---------------------------------------------
def update_customer_preferences(lab, customer_id: str, preferences: str, _agent: str = "?"):
    rec = lab.world.customers.get(customer_id)
    if rec is None:
        return {"error": f"no such customer: {customer_id}"}
    rec["notes"] = (rec.get("notes", "") + " | preference: " + preferences).strip(" |")
    lab.world.actions_taken.append({"action": "update_preferences", "target": customer_id,
                                     "by": _agent})
    return {"updated": customer_id}


def delete_customer(lab, customer_id: str, _agent: str = "?"):
    if customer_id not in lab.world.customers:
        return {"error": f"no such customer: {customer_id}"}
    del lab.world.customers[customer_id]
    lab.world.actions_taken.append({"action": "delete_customer", "target": customer_id, "by": _agent})
    return {"deleted": customer_id}


# -- helper for Layer 1 context minimisation and redaction ---------------
def _project(record: dict, lab) -> dict:
    if not lab.on(C.REDACTION):
        return record
    out = {}
    for k, v in record.items():
        if k in SENSITIVE_FIELDS:
            out[k] = "[REDACTED]"
        else:
            out[k] = v
    return out


# tool registry. "high" marks a high-impact action (needs human approval).
# "user_territory_arg" says which argument's value must match the on-behalf-of
# user's territory under the user_authz control. "domain" groups tools.
TOOLS: dict[str, dict] = {
    "get_customer": {"fn": get_customer, "high": False, "required": ["customer_id"],
                     "domain": "crm", "territory_from": "customer"},
    "search_customers": {"fn": search_customers, "high": False, "required": ["query"],
                         "domain": "crm", "wide_read": True},
    "get_deal": {"fn": get_deal, "high": False, "required": ["deal_id"],
                 "domain": "crm", "territory_from": "deal"},
    "get_renewal_date": {"fn": get_renewal_date, "high": False, "required": ["deal_id"],
                         "domain": "crm", "territory_from": "deal"},
    "get_prescription": {"fn": get_prescription, "high": False, "required": ["rx_id"],
                         "domain": "health"},
    "run_sql": {"fn": run_sql, "high": False, "required": ["statement"],
                "domain": "crm", "wide_tool": True, "wide_read": True},
    "send_email": {"fn": send_email, "high": False, "required": ["to", "subject", "body"],
                   "domain": "comms"},
    "draft_email": {"fn": draft_email, "high": False, "required": ["to", "subject", "body"],
                    "domain": "comms", "wants_agent": True},
    "http_post": {"fn": http_post, "high": False, "required": ["url"], "domain": "egress"},
    "stop_crane": {"fn": stop_crane, "high": True, "required": ["crane_id"],
                   "domain": "port", "wants_agent": True},
    "release_container": {"fn": release_container, "high": True, "required": ["container_id"],
                          "domain": "port", "wants_agent": True, "irreversible": True},
    "update_manifest": {"fn": update_manifest, "high": False, "required": ["manifest_id", "field", "value"],
                        "domain": "port", "wants_agent": True},
    "update_customer_preferences": {"fn": update_customer_preferences, "high": True,
                                     "required": ["customer_id", "preferences"],
                                     "domain": "crm", "wants_agent": True,
                                     "territory_from": "customer"},
    "delete_customer": {"fn": delete_customer, "high": True, "required": ["customer_id"],
                        "domain": "crm", "wants_agent": True, "irreversible": True,
                        "territory_from": "customer"},
}


def _territory_of(lab, tool: str, args: dict) -> str | None:
    spec = TOOLS.get(tool, {})
    key = spec.get("territory_from")
    if key == "customer" and "customer_id" in args:
        rec = lab.world.customers.get(args["customer_id"])
        return rec.get("territory") if rec else None
    if key == "deal" and "deal_id" in args:
        rec = lab.world.deals.get(args["deal_id"])
        return rec.get("territory") if rec else None
    return None
