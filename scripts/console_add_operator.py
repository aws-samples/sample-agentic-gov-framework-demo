#!/usr/bin/env python3
"""
Create or update a local-mode console operator.

Writes the operators file used by CONSOLE_AUTH_MODE=local (default
~/.fsi-console/operators.json, override with --file or
CONSOLE_OPERATORS_FILE), outside the repo. The password is read with getpass
(never from argv or the environment), stored as an scrypt hash
(n=16384, r=8, p=1), and the file is replaced atomically (os.replace) with
mode 0600 inside a 0700 directory.

Usage:
    python scripts/console_add_operator.py --operator-id alice \
        --display-name "Alice Analyst" --roles operator,auditor \
        [--aws-profile operator=fsi-operator --aws-profile auditor=fsi-auditor]
"""
import argparse
import base64
import getpass
import json
import os
import secrets
import sys
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import console_auth  # noqa: E402
from app.console_identity import CONSOLE_ROLES, PURPOSES  # noqa: E402

MIN_PASSWORD_CHARS = 12


def _parse_roles(raw: str) -> list:
    roles = [r.strip() for r in raw.split(",") if r.strip()]
    if not roles or len(set(roles)) != len(roles) or not set(roles) <= CONSOLE_ROLES:
        raise ValueError(f"--roles must be a comma-separated subset of {sorted(CONSOLE_ROLES)}")
    return roles


def _parse_profiles(values: list) -> dict:
    profiles = {}
    for value in values or []:
        purpose, sep, name = value.partition("=")
        if not sep or purpose not in PURPOSES or purpose in profiles \
                or not console_auth.AWS_PROFILE_NAME_RE.fullmatch(name):
            raise ValueError("--aws-profile must be <operator|approver|auditor>=<profile name>")
        profiles[purpose] = name
    return profiles


def _read_password() -> str:
    first = getpass.getpass("New password: ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        raise ValueError("passwords do not match")
    if len(first) < MIN_PASSWORD_CHARS:
        raise ValueError(f"password must be at least {MIN_PASSWORD_CHARS} characters")
    return first


def _load_existing(path: str) -> list:
    """Existing entries, re-validated with the console's own loader (which also
    enforces ownership and 0600). A missing file starts a new one."""
    try:
        console_auth.load_operators(path)
    except console_auth.ConsoleAuthConfigError as exc:
        if exc.code == console_auth.OPERATORS_FILE_MISSING:
            return []
        raise
    with open(path, encoding="utf-8") as f:
        return json.load(f)["operators"]


def build_entry(operator_id: str, display_name: str, roles: list, profiles: dict,
                password: str) -> dict:
    salt = secrets.token_bytes(console_auth.SCRYPT_SALT_BYTES)
    dk = console_auth.hash_password(password, salt)
    entry = {
        "operator_id": operator_id,
        "display_name": display_name,
        "roles": roles,
        "scrypt": {
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "n": console_auth.SCRYPT_N,
            "r": console_auth.SCRYPT_R,
            "p": console_auth.SCRYPT_P,
            "dk_b64": base64.b64encode(dk).decode("ascii"),
        },
    }
    if profiles:
        entry["aws_profiles"] = profiles
    return entry


def write_operators_file(path: str, entries: list) -> None:
    document = {"version": 1, "operators": entries}
    console_auth.parse_operators_document(document)  # never write a file the console would refuse
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".operators-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(document, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Create or update a local console operator")
    parser.add_argument("--operator-id", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--roles", required=True, help="comma-separated: operator,approver,auditor")
    parser.add_argument("--aws-profile", action="append", default=[],
                        help="<purpose>=<AWS profile name>; repeat per purpose")
    parser.add_argument("--file", default=None, help="operators file (default: CONSOLE_OPERATORS_FILE "
                                                     "or ~/.fsi-console/operators.json)")
    args = parser.parse_args(argv)

    path = os.path.expanduser(args.file) if args.file else console_auth.operators_file_path()
    try:
        if not console_auth.OPERATOR_ID_RE.fullmatch(args.operator_id):
            raise ValueError("--operator-id must match ^[a-z][a-z0-9_-]{2,31}$")
        if not 1 <= len(args.display_name) <= 64:
            raise ValueError("--display-name must be 1-64 characters")
        roles = _parse_roles(args.roles)
        profiles = _parse_profiles(args.aws_profile)
        entries = [e for e in _load_existing(path) if e.get("operator_id") != args.operator_id]
        if len(entries) >= console_auth.MAX_OPERATORS:
            raise ValueError(f"at most {console_auth.MAX_OPERATORS} operators are supported")
        password = _read_password()
        entries.append(build_entry(args.operator_id, args.display_name, roles, profiles, password))
        write_operators_file(path, entries)
    except (ValueError, console_auth.ConsoleAuthConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Operator {args.operator_id} saved to {path} (mode 0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
