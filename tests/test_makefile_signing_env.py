"""
Test: Makefile placement of ALLOW_LOCAL_DEV_SIGNING and the governed deploy
chain.

- Every recipe line that runs the run-and-report gate (compliance_gate.py
  without --sign), a demo, a local shim, the Streamlit console or the cached
  output generator sets ALLOW_LOCAL_DEV_SIGNING=true.
- package / gate-sign / verify-gate-artifact / deploy never set it.
- deploy = package -> gate-sign -> verify-gate-artifact (no `gate`).
- gate-sign requires GATE_SIGNER_PROFILE and applies it only to the gate
  command; the cdk deploy and runtime-deploy lines carry no AWS_PROFILE=.
Text parse of the Makefile plus `make -n` (list argv; nothing executes).
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = PROJECT_ROOT / "Makefile"
FLAG = "ALLOW_LOCAL_DEV_SIGNING"
TARGET_RE = re.compile(r"^([A-Za-z0-9_-]+):(?!=)(.*)$")
NEVER = ("package", "gate-sign", "verify-gate-artifact", "deploy")


def _parse():
    targets, prereqs, current = {}, {}, None
    for line in MAKEFILE.read_text(encoding="utf-8").splitlines():
        m = TARGET_RE.match(line)
        if m:
            current = m.group(1)
            targets[current] = []
            prereqs[current] = m.group(2).split("##")[0].split()
        elif line.startswith("\t") and current:
            targets[current].append(line)
        elif line and not line.startswith(("\t", "#")):
            current = None
    return targets, prereqs


def _needs_flag(line):
    if "compliance_gate.py" in line and "--sign" not in line:
        return True
    return bool(re.search(r"demos/[A-Za-z0-9_]+\.py|agentcore/[a-z_]+/main\.py|streamlit run|"
                          r"scripts/generate_cached_output\.py", line))


def test_every_local_reader_recipe_sets_the_opt_in():
    targets, _ = _parse()
    checked = []
    for target, lines in targets.items():
        for line in lines:
            if _needs_flag(line):
                checked.append(target)
                assert f"{FLAG}=true" in line, f"{target}: {line.strip()}"
    expected = {"gate", "demo-detect", "demo-pan", "demo-sar", "demo-challenge", "demo-gate-fail",
                "demo-model-swap", "model-swap-restore", "demo-model-assurance", "demo-circuit-breaker",
                "demo-drift", "demo-detect-live", "demo-pan-live", "demo-sar-live", "demo-challenge-live",
                "demo-circuit-breaker-live", "demo-drift-live", "dev-detection", "dev-compliance",
                "dev-executor", "ui", "ui-live", "generate-cache"}
    assert expected <= set(checked)


def test_deploy_chain_targets_never_set_the_opt_in():
    targets, _ = _parse()
    for target in NEVER:
        assert target in targets, target
        for line in targets[target]:
            assert FLAG not in line, f"{target}: {line.strip()}"


def test_deploy_runs_package_gate_sign_verify_and_not_gate():
    _, prereqs = _parse()
    assert prereqs["deploy"][:3] == ["package", "gate-sign", "verify-gate-artifact"]
    assert "gate" not in prereqs["deploy"]


def test_aws_profile_override_only_on_the_gate_sign_line():
    targets, _ = _parse()
    gate_sign = [line for line in targets["gate-sign"] if "compliance_gate.py" in line]
    assert gate_sign == ["\tAWS_PROFILE=$(GATE_SIGNER_PROFILE) $(PYTHON) compliance_gate.py --sign --bundles-dir build/agentcore"]
    for target, lines in targets.items():
        for line in lines:
            if "AWS_PROFILE=" in line:
                assert target == "gate-sign", f"{target}: {line.strip()}"
    deploy_lines = targets["deploy"]
    assert any("cdk deploy" in line for line in deploy_lines)
    assert any("deploy_agentcore_runtimes.py" in line for line in deploy_lines)
    assert any("--package-only" in line for line in targets["package"])


MAKE = shutil.which("make")


@pytest.mark.skipif(MAKE is None, reason="make not installed")
def test_make_n_gate_sign_requires_the_signer_profile():
    result = subprocess.run(  # nosec B603 -- list argv, resolved make, dry run only
        [MAKE, "-n", "gate-sign"], cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert "GATE_SIGNER_PROFILE must name an AWS profile" in result.stderr


@pytest.mark.skipif(MAKE is None, reason="make not installed")
def test_make_n_gate_sign_applies_the_profile_to_the_gate_only():
    result = subprocess.run(  # nosec B603 -- list argv, resolved make, dry run only
        [MAKE, "-n", "gate-sign", "GATE_SIGNER_PROFILE=x", "PYTHON=python3"],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines == ["AWS_PROFILE=x python3 compliance_gate.py --sign --bundles-dir build/agentcore"]
