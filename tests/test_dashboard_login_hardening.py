"""
Test: Dashboard login gate hardening,
retargeted at per-operator console authentication.

The shared DASHBOARD_PASSWORD and the process-wide lockout are replaced by
app/console_auth.py (per-operator scrypt credentials, per-identity
throttle). The properties this file has always guarded still hold:

1. Constant-time compare: the derived key is compared with
   hmac.compare_digest on bytes, never with `==`.
2. Non-ASCII passwords never crash a sign-in attempt, and a non-ASCII
   configured password still authenticates.
3. The throttle is process state, not st.session_state: opening a new
   browser session does not reset it.
4. Rendering is blocked when unauthenticated: the dashboard shows the
   sign-in page only (no sidebar, no page buttons).
"""
import ast
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from app import console_identity as _console_identity  # noqa: E402

_REAL_STATE = _console_identity._state
DASHBOARD_PATH = os.path.join(PROJECT_ROOT, "app", "dashboard.py")
CONSOLE_AUTH_PATH = os.path.join(PROJECT_ROOT, "app", "console_auth.py")

PASSWORD = "correct-password-1"  # gitleaks:allow -- fake fixture: test-only login password, no real account
NON_ASCII_PASSWORD = "pássword-☃-ünïcode"


def _read(path) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def auth(tmp_path, monkeypatch):
    """console_auth with a real 0600 operators file and per-test state."""
    from app import console_auth, console_identity
    from scripts import console_add_operator

    path = tmp_path / "ops" / "operators.json"
    console_add_operator.write_operators_file(str(path), [
        console_add_operator.build_entry("alice", "Alice", ["operator"], {}, PASSWORD),
        console_add_operator.build_entry("carol", "Carol", ["operator"], {}, NON_ASCII_PASSWORD),
    ])
    monkeypatch.setenv("CONSOLE_OPERATORS_FILE", str(path))
    console_auth._reset_throttle_for_tests()
    state = {}
    monkeypatch.setattr(console_identity, "_state", lambda: state)
    yield console_auth, console_auth.load_operators(), state
    console_auth._reset_throttle_for_tests()


class TestConstantTimeComparison:
    def test_uses_hmac_compare_digest_for_password_check(self):
        code = _read(CONSOLE_AUTH_PATH)
        assert "import hmac" in code
        # Bytes vs bytes (the scrypt output and the stored dk), so a non-ASCII
        # input can never raise TypeError inside compare_digest.
        assert "hmac.compare_digest(derived, target.dk)" in code

    def test_no_plain_equality_on_secrets(self):
        tree = ast.parse(_read(CONSOLE_AUTH_PATH))
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "verify_local_credentials")
        for node in ast.walk(fn):
            if isinstance(node, ast.Compare) and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
                names = {ast.unparse(x) for x in [node.left, *node.comparators]}
                assert not names & {"derived", "target.dk", "password"}, ast.unparse(node)

    def test_compare_digest_is_what_decides(self, auth, monkeypatch):
        console_auth, operators, _ = auth
        calls = []
        real = console_auth.hmac.compare_digest
        monkeypatch.setattr(console_auth.hmac, "compare_digest",
                            lambda a, b: calls.append((type(a), type(b))) or real(a, b))
        assert console_auth.verify_local_credentials("alice", PASSWORD, operators).principal
        assert calls == [(bytes, bytes)]

    def test_dashboard_has_no_shared_password_compare_left(self):
        code = _read(DASHBOARD_PATH)
        assert "_configured_password" not in code
        assert "entered == configured_password" not in code
        assert "compare_digest" not in code  # verification lives in console_auth only


class TestNoGlobalLockout:
    def test_process_wide_lockout_globals_are_gone(self):
        code = _read(DASHBOARD_PATH)
        for name in ("_LOGIN_ATTEMPTS", "_LOGIN_LOCKED_UNTIL", "_login_lockout_remaining",
                     "_MAX_LOGIN_ATTEMPTS", "_LOCKOUT_SECONDS", "_LOGIN_STATE_LOCK"):
            assert name not in code

    def test_require_login_is_a_thin_wrapper(self):
        tree = ast.parse(_read(DASHBOARD_PATH))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "require_login")
        assert "console_auth.authenticate_or_render_sign_in()" in ast.unparse(fn)
        assert 'st.session_state["authenticated"]' not in _read(DASHBOARD_PATH)

    def test_throttle_is_module_state_guarded_by_a_lock(self):
        code = _read(CONSOLE_AUTH_PATH)
        assert "_THROTTLE_LOCK = threading.Lock()" in code
        assert "st.session_state" not in code.split("# ─── Per-identity throttle")[1].split(
            "@dataclass(frozen=True)\nclass SignInResult")[0]


class TestModuleLevelThrottleBehavior:
    """The throttle must survive a brand-new browser session."""

    def _fresh_dashboard_module(self, monkeypatch):
        """Import app/dashboard.py with Streamlit/plotly and app.invoke_live
        stubbed (no running server, no AWS). Unauthenticated: console_auth
        renders the sign-in page and the stubbed st.stop() is a no-op, so the
        module still imports for the helper tests (tests/test_dashboard_pacing.py)."""
        import importlib
        import types
        from unittest.mock import MagicMock

        fake_st = MagicMock()
        fake_session_state = {}
        fake_st.session_state = fake_session_state
        fake_st.get_option.return_value = "127.0.0.1"

        class _FakeForm:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        fake_st.form.side_effect = lambda *a, **k: _FakeForm()
        fake_st.text_input.return_value = ""
        fake_st.form_submit_button.return_value = False
        monkeypatch.setitem(sys.modules, "streamlit", fake_st)

        fake_plotly_go = types.ModuleType("plotly.graph_objects")
        fake_plotly = types.ModuleType("plotly")
        fake_plotly.graph_objects = fake_plotly_go
        monkeypatch.setitem(sys.modules, "plotly", fake_plotly)
        monkeypatch.setitem(sys.modules, "plotly.graph_objects", fake_plotly_go)

        import app.invoke_live as real_invoke_live
        fake_invoke_live = types.ModuleType("app.invoke_live")
        for name in dir(real_invoke_live):
            if not name.startswith("__"):
                value = getattr(real_invoke_live, name)
                setattr(fake_invoke_live, name, (lambda *a, **k: None) if callable(value) else value)
        fake_invoke_live.DriftInjectionRefused = real_invoke_live.DriftInjectionRefused
        monkeypatch.setitem(sys.modules, "app.invoke_live", fake_invoke_live)

        monkeypatch.delenv("CONSOLE_AUTH_MODE", raising=False)
        monkeypatch.setenv("DASHBOARD_PASSWORD", "correct-password")  # ignored

        if "app.dashboard" in sys.modules:
            del sys.modules["app.dashboard"]
        module = importlib.import_module("app.dashboard")
        return module, fake_st, fake_session_state

    def test_attempt_count_persists_across_simulated_session_reset(self, auth):
        console_auth, operators, state = auth
        console_auth.verify_local_credentials("alice", "wrong-password", operators, now=1000.0)
        state.clear()  # a brand-new browser session
        console_auth.verify_local_credentials("alice", "wrong-password", operators, now=1000.0)
        assert console_auth._KNOWN_THROTTLE["alice"][0] == 2

    def test_backoff_applies_across_simulated_sessions(self, auth):
        console_auth, operators, state = auth
        for _ in range(3):
            state.clear()  # a new "session" each time
            console_auth.verify_local_credentials("alice", "wrong-password", operators, now=1000.0)
        state.clear()
        result = console_auth.verify_local_credentials("alice", PASSWORD, operators, now=1000.1)
        assert result.principal is None and result.retry_after > 0

    def test_successful_login_resets_that_operators_throttle(self, auth):
        console_auth, operators, _ = auth
        for _ in range(2):
            console_auth.verify_local_credentials("alice", "wrong-password", operators, now=1000.0)
        assert console_auth.verify_local_credentials("alice", PASSWORD, operators, now=1000.0).principal
        assert "alice" not in console_auth._KNOWN_THROTTLE

    def test_non_ascii_password_attempt_does_not_raise_and_still_throttles(self, auth):
        console_auth, operators, _ = auth
        result = console_auth.verify_local_credentials("alice", "wrong-pássword-☃", operators, now=1000.0)
        assert result.principal is None
        assert console_auth._KNOWN_THROTTLE["alice"][0] == 1

    def test_non_ascii_configured_password_can_still_authenticate(self, auth):
        console_auth, operators, _ = auth
        assert console_auth.verify_local_credentials("carol", NON_ASCII_PASSWORD, operators).principal

    def test_dashboard_imports_with_auth_unconfigured(self, monkeypatch):
        module, fake_st, state = self._fresh_dashboard_module(monkeypatch)
        assert module.require_login() is False
        assert "principal" not in state
        fake_st.stop.assert_called()


class TestRenderingBlockedWhenUnauthenticated:
    @pytest.fixture
    def apptest(self, auth, monkeypatch, tmp_path):
        from app import console_auth, console_identity
        from streamlit.testing.v1 import AppTest
        monkeypatch.setattr(console_identity, "_state", _REAL_STATE)  # real st.session_state
        monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
        monkeypatch.setattr(console_auth, "_server_address", lambda: "127.0.0.1")
        return lambda: AppTest.from_file(DASHBOARD_PATH, default_timeout=60)

    @pytest.mark.parametrize("mode", [None, "local"])
    def test_no_page_renders_without_a_principal(self, apptest, monkeypatch, mode):
        if mode is None:
            monkeypatch.delenv("CONSOLE_AUTH_MODE", raising=False)
        else:
            monkeypatch.setenv("CONSOLE_AUTH_MODE", mode)
        monkeypatch.setenv("DASHBOARD_PASSWORD", PASSWORD)  # never authenticates anything
        at = apptest().run()
        assert not at.exception
        assert len(at.sidebar.radio) == 0
        assert [b.label for b in at.button] in ([], ["Sign in"])
        assert [t.value for t in at.title] == ["FSI Agentic Compliance — Sign in"]

    def test_legacy_password_field_alone_never_signs_in(self, apptest, monkeypatch):
        monkeypatch.setenv("CONSOLE_AUTH_MODE", "local")
        monkeypatch.setenv("DASHBOARD_PASSWORD", PASSWORD)
        at = apptest().run()
        at.text_input[1].set_value(PASSWORD)  # password only, no operator id
        at.button[0].click().run()
        assert "principal" not in at.session_state
        assert len(at.sidebar.radio) == 0

