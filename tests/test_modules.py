"""Every attack must work when its control is off and be blocked when it is on."""
import pytest

from au import controls as C
from au.modules import MODULES, get, run_module
from au.maestro import LAYERS, layers_for_module

NUMBERS = [m.number for m in MODULES]
ATTACK_MODULES = [m.slug for m in MODULES if m.slug != "maestro-threat-model"]


def test_registry_is_numbered_in_order():
    assert [m.number for m in MODULES] == list(range(1, len(MODULES) + 1))
    assert get(1) is get("1") is get("optus-overprivilege")
    assert get(8).slug == "maestro-threat-model"


@pytest.mark.parametrize("slug", ATTACK_MODULES)
def test_attack_succeeds_when_controls_are_off(slug):
    lab, _ = run_module(slug, "vulnerable")
    assert lab.damage(), f"{slug} must be exploitable when the right controls are off"


@pytest.mark.parametrize("slug", ATTACK_MODULES)
def test_attack_blocked_when_secured(slug):
    lab, extra = run_module(slug, "secured")
    assert lab.damage() == [], f"{slug}: secured mode leaked: {lab.damage()}"
    assert extra["legit_ok"], f"{slug}: hardening broke the legitimate workflow"
    assert lab.audit.verify()[0] is True


@pytest.mark.parametrize("slug", ATTACK_MODULES)
def test_legitimate_work_completes_when_vulnerable(slug):
    assert run_module(slug, "vulnerable")[1]["legit_ok"]


def test_module_1_user_authz_catches_cross_territory_read():
    lab, _ = run_module(1, "vulnerable")
    msgs = lab.damage()
    assert any("C-103 in QLD" in d for d in msgs)
    assert any("C-104 in WA" in d for d in msgs)


def test_module_2_defence_in_depth():
    # trust_label alone off: narrow_tool and egress still catch it.
    lab, _ = run_module(2, disabled={C.TRUST_LABEL})
    assert lab.damage() == []
    # narrow_tool alone off: still caught by egress (external destinations) and trust_label (ignores directives).
    lab, _ = run_module(2, disabled={C.NARROW_TOOL})
    assert lab.damage() == []
    # All three off: the full chain lets the exfil through.
    lab, _ = run_module(2, disabled={C.TRUST_LABEL, C.NARROW_TOOL, C.EGRESS})
    assert lab.damage(), "with trust_label, narrow_tool and egress all off, the exfil should succeed"


def test_module_3_tampered_skill_damage_names_the_skill():
    lab, extra = run_module(3, "vulnerable")
    assert any("promo-finder" in d for d in lab.damage())
    assert extra["tampered_loaded"] is True


def test_module_4_redaction_and_context_min_overlap():
    # Only redaction off: context_min still trims.
    lab, _ = run_module(4, disabled={C.REDACTION})
    assert lab.damage() == []
    # Only context_min off: redaction still strips.
    lab, _ = run_module(4, disabled={C.CONTEXT_MIN})
    assert lab.damage() == []
    # Both off: sensitive field leaks.
    lab, _ = run_module(4, disabled={C.CONTEXT_MIN, C.REDACTION})
    assert any("sensitive health field" in d for d in lab.damage())


def test_module_5_release_without_authority():
    lab, _ = run_module(5, "vulnerable")
    assert any("release_container" in d for d in lab.damage())
    # Secured: the approver is not authorised, so the attack is blocked.
    lab, _ = run_module(5, "secured")
    assert lab.damage() == []


def test_module_6_misleading_approval_damage_names_the_mismatch():
    lab, extra = run_module(6, "vulnerable")
    dmg = lab.damage()
    assert any("C-104" in d and "C-101" in d for d in dmg)
    assert extra["human_decision"] == "approved"      # the human WAS misled in vulnerable
    # Secured: the card is trustworthy, the human denies.
    lab, extra = run_module(6, "secured")
    assert lab.damage() == []
    assert extra["human_decision"] == "denied"


def test_capstone_single_control_removal_matches_the_solution():
    lets_through = {c for c in C.ALL if run_module(7, disabled={c})[0].damage()}
    assert lets_through == {C.USER_AUTHZ, C.SUPPLY_CHAIN,
                            C.HITL_BINDING, C.APPROVAL_DISPLAY}
    # Removing any one control, the legitimate workflow still completes.
    for c in C.ALL:
        assert run_module(7, disabled={c})[1]["legit_ok"]


def test_maestro_module_is_analytical_and_safe():
    lab, extra = run_module(8, "secured")
    assert lab.damage() == []
    assert extra["legit_ok"] and extra.get("analytical")


def test_every_lab_control_sits_in_a_maestro_layer():
    all_maestro = {c for L in LAYERS for c in L["controls"]}
    # Every control appears in at least one MAESTRO layer.
    missing = set(C.ALL) - all_maestro
    assert missing == set(), f"these controls are not mapped to a MAESTRO layer: {missing}"
