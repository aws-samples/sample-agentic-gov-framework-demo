"""
Test: demo_detect / demo_sar / demo_challenge can actually run live.
- Each parser defaults to local mode; --no-local selects live mode.
  (`--local` used to be store_true with default=True, so it could never be
  turned off and the -live targets silently ran the cached fixture.)
- Each matching *-live Makefile target passes --no-local; the local targets
  keep --local and never pass --no-local.
"""
import importlib.util
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = PROJECT_ROOT / "Makefile"
TARGET_RE = re.compile(r"^([A-Za-z0-9_-]+):(?!=)")
DEMOS = {"demo_detect": "demo-detect", "demo_sar": "demo-sar", "demo_challenge": "demo-challenge"}


def _load(name):
    spec = importlib.util.spec_from_file_location(name, PROJECT_ROOT / "demos" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _recipes():
    targets, current = {}, None
    for line in MAKEFILE.read_text(encoding="utf-8").splitlines():
        m = TARGET_RE.match(line)
        if m:
            current = m.group(1)
            targets[current] = []
        elif line.startswith("\t") and current:
            targets[current].append(line)
        elif line and not line.startswith(("\t", "#")):
            current = None
    return targets


@pytest.mark.parametrize("name", sorted(DEMOS))
def test_parser_defaults_to_local(name):
    assert _load(name).build_parser().parse_args([]).local is True
    assert _load(name).build_parser().parse_args(["--local"]).local is True


@pytest.mark.parametrize("name", sorted(DEMOS))
def test_no_local_selects_live(name):
    assert _load(name).build_parser().parse_args(["--no-local"]).local is False


def test_detect_live_mode_resolves_to_cpu():
    args = _load("demo_detect").build_parser().parse_args(["--no-local", "--mode", "cpu"])
    assert ("local" if args.local else args.mode) == "cpu"


@pytest.mark.parametrize("name", sorted(DEMOS))
def test_live_target_passes_no_local(name):
    lines = [line for line in _recipes()[f"{DEMOS[name]}-live"] if f"demos/{name}.py" in line]
    assert len(lines) == 1
    assert "--no-local" in lines[0].split()


@pytest.mark.parametrize("name", sorted(DEMOS))
def test_local_target_stays_local(name):
    lines = [line for line in _recipes()[DEMOS[name]] if f"demos/{name}.py" in line]
    assert len(lines) == 1
    assert "--local" in lines[0].split()
    assert "--no-local" not in lines[0]
