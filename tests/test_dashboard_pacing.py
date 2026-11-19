"""
Test: dashboard demo pacing helpers (semgrep arbitrary-sleep hardening).

Cosmetic pauses go through _demo_pause (scaled by DEMO_PACING_SECONDS_SCALE,
default 1.0, 0 disables). There is no other direct sleep: the old shared-
password login backoff moved to app/console_auth.py's per-identity throttle,
which never sleeps.
"""
import ast
import os

import pytest

# Module import (not `from ... import Test...`) so pytest does not collect
# the login-hardening test class a second time from this module.
import test_dashboard_login_hardening as _login_tests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_PATH = os.path.join(PROJECT_ROOT, "app", "dashboard.py")


@pytest.fixture
def dash(monkeypatch):
    harness = _login_tests.TestModuleLevelThrottleBehavior()
    module, _fake_st, _state = harness._fresh_dashboard_module(monkeypatch)
    slept = []
    monkeypatch.setattr(module.time, "sleep", slept.append)
    return module, slept


def test_default_scale_keeps_demo_timing(dash, monkeypatch):
    module, slept = dash
    monkeypatch.delenv("DEMO_PACING_SECONDS_SCALE", raising=False)
    module._demo_pause(0.3)
    assert slept == [0.3]


def test_zero_disables_pauses(dash, monkeypatch):
    module, slept = dash
    monkeypatch.setenv("DEMO_PACING_SECONDS_SCALE", "0")
    module._demo_pause(0.3)
    assert slept == []


def test_scale_multiplies(dash, monkeypatch):
    module, slept = dash
    monkeypatch.setenv("DEMO_PACING_SECONDS_SCALE", "0.5")
    module._demo_pause(0.3)
    assert slept == [pytest.approx(0.15)]


@pytest.mark.parametrize("raw", ["abc", "-1", "nan", "inf", "  "])
def test_invalid_values_fall_back_to_default(dash, monkeypatch, raw):
    module, slept = dash
    monkeypatch.setenv("DEMO_PACING_SECONDS_SCALE", raw)
    module._demo_pause(0.3)
    assert slept == [0.3]


def test_scale_is_capped(dash, monkeypatch):
    module, slept = dash
    monkeypatch.setenv("DEMO_PACING_SECONDS_SCALE", "1000")
    module._demo_pause(0.3)
    assert slept == [pytest.approx(3.0)]


def test_no_fixed_alarm_wait_remains():
    """The old fixed 2 s 'alarm evaluating' wait on page 3.1 could never
    observe a trip (the live alarm needs >= 20 clusters/min for 2 minutes);
    it was removed in favor of reading the breaker's real state."""
    with open(DASHBOARD_PATH, encoding="utf-8") as f:
        src = f.read()
    assert "_wait_for_alarm_evaluation" not in src


def test_no_literal_sleeps_outside_helpers():
    with open(DASHBOARD_PATH, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    helper_ranges = [
        (n.lineno, n.end_lineno) for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_demo_pause"
    ]
    assert len(helper_ranges) == 1
    sleeps = [n for n in ast.walk(tree)
              if isinstance(n, ast.Call) and ast.unparse(n.func) == "time.sleep"]
    literal_outside = [
        n.lineno for n in sleeps
        if n.args and isinstance(n.args[0], ast.Constant)
        and not any(lo <= n.lineno <= hi for lo, hi in helper_ranges)
    ]
    assert literal_outside == []
    # No direct sleep remains outside the pacing helper (the shared-password
    # login backoff is gone; console_auth's throttle refuses, never sleeps).
    outside = [ast.unparse(n) for n in sleeps
               if not any(lo <= n.lineno <= hi for lo, hi in helper_ranges)]
    assert outside == []
