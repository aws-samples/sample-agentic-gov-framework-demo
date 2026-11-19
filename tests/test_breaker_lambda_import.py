"""
The breaker handler imports in the Lambda layout (only the asset dir on
sys.path, no repo root, no circuit_breaker package) and from the repo root.
A `from circuit_breaker.…` import inside handler.py would fail
the first test (a module that only imports from the repo root breaks in Lambda).
"""
import glob
import os
import shutil
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BREAKER_DIR = os.path.join(PROJECT_ROOT, "circuit_breaker")

# -I drops cwd/PYTHONPATH; the filter also drops anything under the repo root
# (keeping the stdlib and site-packages), so only the asset dir provides modules.
_IMPORT_SCRIPT = (
    "import sys; root = sys.argv[2]; "
    "sys.path[:] = [sys.argv[1]] + [p for p in sys.path if p and not p.startswith(root)]; "
    "import handler; assert handler.identity_proof.verify_identity; assert handler.authz.classify; "
    "assert handler.governance_state.__name__ == 'governance_state'; "
    "assert not any(m == 'circuit_breaker' or m.startswith('circuit_breaker.') for m in sys.modules)"
)


def test_imports_with_only_the_asset_dir_on_sys_path(tmp_path):
    task = tmp_path / "task"
    task.mkdir()
    for path in glob.glob(os.path.join(BREAKER_DIR, "*.py")):
        shutil.copy(path, task)
    assert not (task / "__init__.py").exists()
    result = subprocess.run(  # nosec B603 -- static list argv, no shell
        [sys.executable, "-I", "-c", _IMPORT_SCRIPT, str(task), PROJECT_ROOT],
        cwd=task,
        env={"AWS_LAMBDA_FUNCTION_NAME": "x", "AWS_DEFAULT_REGION": "us-east-1", "PATH": os.environ["PATH"]},
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stderr


def test_imports_from_repo_root_as_namespace_package():
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
    import circuit_breaker.handler as handler
    assert handler.identity_proof.__name__ == "identity_proof"
    assert handler.authz.__name__ == "authz"
    assert handler.governance_state.__name__ == "governance_state"
    assert not os.path.exists(os.path.join(BREAKER_DIR, "__init__.py"))


_SCRIPT_IMPORT = (
    "import importlib.util, sys; "
    "spec = importlib.util.spec_from_file_location('break_glass_release', sys.argv[1]); "
    "module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); "
    "assert module.governance_state.__name__ == 'circuit_breaker.governance_state'; "
    "assert module.governance_state.read and module.governance_state.claim_break_glass"
)


def test_break_glass_script_imports_governance_state_from_the_repo_root():
    script = os.path.join(PROJECT_ROOT, "scripts", "break_glass_release.py")
    result = subprocess.run(  # nosec B603 -- static list argv, no shell
        [sys.executable, "-I", "-c", _SCRIPT_IMPORT, script],
        cwd=PROJECT_ROOT, env={"AWS_DEFAULT_REGION": "us-east-1", "PATH": os.environ["PATH"]},
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stderr
