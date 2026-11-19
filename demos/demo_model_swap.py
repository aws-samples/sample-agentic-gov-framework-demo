#!/usr/bin/env python3
"""
Demo: Deployment Control — a developer swaps the model, the real gate blocks it.

This is the D5 "big finish" and it uses the REAL compliance gate — not a mock.

The realistic threat: a developer changes the model the compliance agent uses
(a one-line edit in a PR) to something that was never approved. The org's
approved-models registry did NOT move — the *code* drifted away from it. The
gate catches exactly this.

  --break   : rewrite the BEDROCK_MODEL_ID default in
              lambdas/compliance_agent/handler.py to an UNAPPROVED model (as a
              bad commit would), then run the REAL ComplianceGate. Model
              Assurance FAILs, the gate exits non-zero, deploy is blocked. The
              handler is LEFT edited (no auto-restore) — a clean stopping point.
  --restore : put handler.py back (off-stage reset; not run during the demo).

Edits the actual file the gate inspects and runs the actual gate, so
"deploy blocked" is real, not theater.
"""
import argparse
import os
import re
import runpy
import shutil
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

HANDLER_REL = "lambdas/compliance_agent/handler.py"
HANDLER = os.path.join(PROJECT_ROOT, "lambdas", "compliance_agent", "handler.py")
BACKUP = os.path.join(PROJECT_ROOT, "lambdas", "compliance_agent", ".handler.backup.py")
GATE_SCRIPT = os.path.join(PROJECT_ROOT, "compliance_gate.py")


def _run_gate() -> int:
    """Run compliance_gate.py in-process and return its exit code.

    runpy executes the repo-local gate script exactly as `python
    compliance_gate.py` would (run_name="__main__" triggers its main()), and
    main() ends in sys.exit(code), which is caught here. No subprocess or shell.
    """
    gate_path = _confined(GATE_SCRIPT)
    # The gate parses sys.argv with argparse; the demo's own flags
    # (--break/--restore) would make it exit 2. Run it with argv isolated to
    # just its own path, and always restore the demo's argv.
    saved_argv = sys.argv
    sys.argv = [gate_path]
    try:
        runpy.run_path(gate_path, run_name="__main__")
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        return code if isinstance(code, int) else 1
    finally:
        sys.argv = saved_argv
    return 0


def _confined(path):
    """Return the real path of `path`, refusing anything outside PROJECT_ROOT
    (symlinks resolved). Guards every path handed to a subprocess."""
    real = os.path.realpath(path)
    if not real.startswith(os.path.realpath(PROJECT_ROOT) + os.sep):
        raise ValueError(f"Refusing path outside the project: {real}")
    return real

# An unapproved model a developer might reach for — NOT on the registry.
UNAPPROVED_MODEL = "us.meta.llama3-3-70b-instruct-v1:0"

# Matches:  MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "<default>")
# The default may be empty (handler.py ships "" so an unset env fails fast),
# hence [^"]* rather than [^"]+.
MODEL_LINE_RE = re.compile(
    r'(MODEL_ID\s*=\s*os\.environ\.get\(\s*"BEDROCK_MODEL_ID"\s*,\s*")([^"]*)("\s*\))'
)

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"; CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"


def _read():
    with open(HANDLER, encoding="utf-8") as f:
        return f.read()


def _write(text):
    with open(HANDLER, "w", encoding="utf-8") as f:
        f.write(text)


def do_break():
    src = _read()
    m = MODEL_LINE_RE.search(src)
    if not m:
        print(f"{RED}Could not find the BEDROCK_MODEL_ID default in handler.py — "
              f"aborting (nothing changed).{RESET}")
        return 2

    current_model = m.group(2)
    if current_model == UNAPPROVED_MODEL:
        print(f"{YELLOW}Handler already points at the unapproved model — run "
              f"'make model-swap-restore' first.{RESET}")
        return 0

    # Back up the good handler so --restore can reset it byte-for-byte.
    if not os.path.exists(BACKUP):
        shutil.copyfile(HANDLER, BACKUP)

    new_src = MODEL_LINE_RE.sub(rf'\g<1>{UNAPPROVED_MODEL}\g<3>', src, count=1)
    _write(new_src)

    print(f"\n{BOLD}{'='*64}{RESET}")
    print(f"{BOLD}  DEPLOYMENT CONTROL — a developer swaps the model in a PR{RESET}")
    print(f"{BOLD}{'='*64}{RESET}")
    print(f"  Edited: {BOLD}lambdas/compliance_agent/handler.py{RESET}")
    print(f"    BEDROCK_MODEL_ID default:")
    print(f"      {GREEN}{current_model or '(empty: model set by the deploy env)'}{RESET}   (approved)")
    print(f"      {RED}{UNAPPROVED_MODEL}{RESET}   (NOT on the registry)")
    print(f"\n  The approved-models registry did not change — the code drifted")
    print(f"  away from it. Now running the {BOLD}real{RESET} compliance gate...\n")

    # Run the REAL gate so the audience sees its true output and the real
    # exit code. It runs in-process (no subprocess, no shell): the gate reads
    # the edited handler.py from disk, exactly as it does in CI.
    returncode = _run_gate()

    print()
    if returncode != 0:
        print(f"  {RED}{BOLD}Gate exit code: {returncode} → DEPLOY BLOCKED.{RESET}")
        print(f"  {RED}An unapproved model was configured and the gate stopped it.{RESET}")
    else:
        print(f"  {YELLOW}Unexpected: gate passed. Check the edit / registry.{RESET}")
    print(f"\n  {BOLD}Key insight:{RESET} the developer didn't touch the approved list —")
    print(f"  they just changed the model. The gate re-derives the check on every")
    print(f"  deploy, so an unapproved model never reaches production.")
    print(f"\n  (Handler left edited. Run {BOLD}make model-swap-restore{RESET} off-stage to reset.)")
    print(f"{'='*64}\n")
    return returncode


def do_restore():
    if os.path.exists(BACKUP):
        shutil.copyfile(BACKUP, HANDLER)
        os.remove(BACKUP)
        print(f"{GREEN}handler.py restored from backup.{RESET}")
        return 0
    # No backup: this script does not shell out to git. Tell the operator the
    # exact restore command instead (off-stage step).
    print(f"{RED}No backup found — restore handler.py from git:{RESET}")
    print(f"  git checkout -- {HANDLER_REL}")
    return 1


def main():
    parser = argparse.ArgumentParser(description="Demo: swap model → real gate blocks")
    parser.add_argument("--break", dest="do_break", action="store_true",
                        help="Swap in an unapproved model and run the real gate (leaves it edited)")
    parser.add_argument("--restore", action="store_true",
                        help="Restore handler.py (off-stage reset)")
    args = parser.parse_args()

    if args.restore:
        sys.exit(do_restore())
    if args.do_break:
        sys.exit(1 if do_break() != 0 else 0)

    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
