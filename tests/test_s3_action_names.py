"""
Offline guard: every S3 IAM action this repo names must be a real IAM action.

CloudFormation rejects a bucket policy that names a non-existent action
("Policy has invalid action") and rolls the whole stack back; a deploy failed
on s3:PutBucketEncryption (the API name; the IAM action is
s3:PutEncryptionConfiguration). The allowlist tests/s3_iam_actions.json is a
committed copy of the Service Authorization Reference for the s3 prefix.
No AWS calls; `make validate-iam` runs IAM Access Analyzer on the full templates.
"""
import fnmatch
import json
import os
import re
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "cdk"))
sys.path.insert(0, PROJECT_ROOT)

from audit_archive import BUCKET_PROTECTION_ACTIONS, OBJECT_LOCKDOWN_ACTIONS  # noqa: E402
import compliance_gate  # noqa: E402

with open(os.path.join(PROJECT_ROOT, "tests", "s3_iam_actions.json"), encoding="utf-8") as _f:
    VALID_S3_ACTIONS = frozenset(json.load(_f)["actions"])

# Python sources that name S3 actions in policies or policy checks.
_SOURCES = ["compliance_gate.py"] + sorted(
    os.path.join("cdk", n) for n in os.listdir(os.path.join(PROJECT_ROOT, "cdk")) if n.endswith(".py"))
_S3_ACTION_LITERAL = re.compile(r"""["'](s3:[A-Za-z*?]+)["']""")


def _valid(action: str) -> bool:
    if any(c in action for c in "*?"):
        return any(fnmatch.fnmatchcase(a, action) for a in VALID_S3_ACTIONS)
    return action in VALID_S3_ACTIONS


def test_allowlist_is_sane():
    assert len(VALID_S3_ACTIONS) > 100
    assert "s3:PutEncryptionConfiguration" in VALID_S3_ACTIONS
    assert "s3:PutBucketEncryption" not in VALID_S3_ACTIONS


@pytest.mark.parametrize("name, actions", [
    ("audit_archive.BUCKET_PROTECTION_ACTIONS", BUCKET_PROTECTION_ACTIONS),
    ("audit_archive.OBJECT_LOCKDOWN_ACTIONS", OBJECT_LOCKDOWN_ACTIONS),
    ("compliance_gate.ARCHIVE_PROTECTION_ACTIONS", compliance_gate.ARCHIVE_PROTECTION_ACTIONS),
    ("compliance_gate.ARCHIVE_LOCKDOWN_ACTIONS", compliance_gate.ARCHIVE_LOCKDOWN_ACTIONS),
])
def test_archive_action_lists_are_valid_iam_actions(name, actions):
    invalid = sorted(a for a in actions if a not in VALID_S3_ACTIONS)
    assert not invalid, f"{name} names actions that are not IAM actions: {invalid}"


def test_gate_and_cdk_lists_agree():
    assert set(BUCKET_PROTECTION_ACTIONS) == compliance_gate.ARCHIVE_PROTECTION_ACTIONS
    assert set(OBJECT_LOCKDOWN_ACTIONS) == compliance_gate.ARCHIVE_LOCKDOWN_ACTIONS


def test_every_s3_action_literal_in_source_is_valid():
    found = {}
    for rel in _SOURCES:
        with open(os.path.join(PROJECT_ROOT, rel), encoding="utf-8") as f:
            for action in _S3_ACTION_LITERAL.findall(f.read()):
                found.setdefault(action, rel)
    assert "s3:PutObject" in found  # the scan is actually finding literals
    invalid = sorted(f"{a} ({rel})" for a, rel in found.items() if not _valid(a))
    assert not invalid, f"not IAM actions (see tests/s3_iam_actions.json): {invalid}"
