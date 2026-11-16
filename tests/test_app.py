"""Smoke test for the browser app. Skipped if Streamlit is not installed."""
import pytest

pytest.importorskip("streamlit")
from pathlib import Path  # noqa: E402

from streamlit.testing.v1 import AppTest  # noqa: E402

from au.modules import MODULES  # noqa: E402

APP = str(Path(__file__).resolve().parent.parent / "app.py")


def _run(mode: str, module: int = 1) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    at.selectbox(key="module").set_value(module).run()
    if module != 8:
        at.radio(key="mode").set_value(mode).run()
    at.button(key="run").click().run()
    assert not at.exception
    return at


def test_secured_run_reports_blocked():
    at = _run("Secured")
    assert any("ATTACK BLOCKED" in s.value for s in at.success)


def test_vulnerable_run_reports_success_of_attack():
    at = _run("Vulnerable")
    assert any("ATTACK SUCCEEDED" in e.value for e in at.error)


def test_every_module_renders_in_both_modes():
    for m in MODULES:
        if m.slug == "maestro-threat-model":
            # Analytical module: only Secured render is valid.
            _run("Secured", m.number)
        else:
            for mode in ("Secured", "Vulnerable"):
                _run(mode, m.number)


def test_maestro_module_renders_the_coverage_report():
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.selectbox(key="module").set_value(8).run()
    at.button(key="run").click().run()
    assert not at.exception
    # Find a MAESTRO expander by label.
    labels = [e.label for e in at.expander if hasattr(e, "label")]
    assert any(label.startswith("L1") for label in labels)
