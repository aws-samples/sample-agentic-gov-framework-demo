"""
Bind packaged agent sources to the HEAD commit.

`tree_clean` alone does not cover gitignored files, and packaging ships every
visible *.py in an agent dir whether it is tracked or not (an extra boto3.py /
json.py next to a handler would shadow the real module). Every packaged
source must therefore be byte-identical to its blob in the HEAD tree.

Used by `compliance_gate.py --sign` and by `scripts/verify_gate_artifact.py`.
All git calls go through a caller-supplied runner `git(argv) ->
CompletedProcess` (list argv, resolved git executable, no shell), so the gate
can route them through its own `_git` seam.
"""
import hashlib
import re
import subprocess  # nosec B404 -- static git argv, list form, no shell (see the nosec B603 on the call)
import zipfile
from pathlib import Path

GIT_TIMEOUT_SECONDS = 30
OBJECT_FORMATS = ("sha1", "sha256")
ALLOWED_BLOB_MODES = ("100644", "100755")

REGISTRY_SIGNATURE_ARCNAME = "data/approved_models.json.sig"
REGISTRY_KMS_SIGNATURE_PATH = "data/approved_models.json.kms.sig"
LOCAL_DEV_MARKER = "LOCAL_DEV_BUILD"

# Arcname -> repo path, in precedence order. The packaging layout
# (cdk/deploy_agentcore_runtimes.py:package_agent) is fixed:
#   skip       lib/ (pip output, bound by hash locks + bundle digest) and
#              governance/ (gate artifact, embedded after signing)
#   root_file  each agent_cfg["root_files"] arcname -> its source path, plus
#              the registry signature: data/approved_models.json.sig ->
#              data/approved_models.json.kms.sig for a non-local-dev build
#   lambdas    lambdas/<dir>/<f>.py        -> the extra_dir named <dir>
#   package    <package>/<f>.py            -> the packages entry named <package>
#   code_dir   <name>.py (top level)       -> agentcore/<agent_dir>/<name>.py
# Anything else is "unmapped" and therefore offending.
ARCNAME_RULES = (
    ("skip", re.compile(r"^(?:lib|governance)/")),
    ("root_file", None),
    ("lambdas", re.compile(r"^lambdas/([A-Za-z0-9_]+)/([A-Za-z0-9_.-]+\.py)$")),
    ("package", re.compile(r"^([A-Za-z0-9_]+)/([A-Za-z0-9_.-]+\.py)$")),
    ("code_dir", re.compile(r"^([A-Za-z0-9_.-]+\.py)$")),
)


class HeadBindingError(Exception):
    """git facts could not be established (fails closed)."""


def default_git_runner(repo_root):
    """Runner executing a list argv in `repo_root` (no shell, bounded)."""
    def run(argv):
        return subprocess.run(  # nosec B603 # nosemgrep -- static git argv, list form, no shell, resolved git_path
            list(argv), cwd=str(repo_root), check=True, capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    return run


def _stdout_bytes(completed) -> bytes:
    out = completed.stdout
    if isinstance(out, str):
        return out.encode("utf-8", "surrogateescape")
    return out or b""


def _run(git, argv):
    try:
        return _stdout_bytes(git(argv))
    except (OSError, subprocess.SubprocessError) as exc:
        raise HeadBindingError(f"git {argv[1] if len(argv) > 1 else ''} failed ({type(exc).__name__})") from exc


def rev_parse_head(git, git_path) -> str:
    head = _run(git, [git_path, "rev-parse", "HEAD"]).decode("ascii", "replace").strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
        raise HeadBindingError("HEAD is not a commit id")
    return head


def porcelain_status(git, git_path) -> list:
    """Lines of `git status --porcelain --untracked-files=all` (empty = clean)."""
    out = _run(git, [git_path, "status", "--porcelain", "--untracked-files=all"])
    return [line for line in out.decode("utf-8", "replace").splitlines() if line.strip()]


def object_format(git, git_path) -> str:
    fmt = _run(git, [git_path, "rev-parse", "--show-object-format"]).decode("ascii", "replace").strip()
    if fmt not in OBJECT_FORMATS:
        raise HeadBindingError(f"unsupported git object format: {fmt!r}")
    return fmt


def head_tree(git, git_path) -> dict:
    """{path: (mode, oid)} for every entry of the HEAD tree."""
    out = _run(git, [git_path, "ls-tree", "-r", "-z", "--full-tree", "HEAD"])
    tree = {}
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, sep, path = record.partition(b"\t")
        parts = meta.split(b" ")
        if not sep or len(parts) != 3:
            raise HeadBindingError("unparseable ls-tree record")
        mode, _type, oid = (p.decode("ascii", "replace") for p in parts)
        tree[path.decode("utf-8", "surrogateescape")] = (mode, oid)
    return tree


def blob_id(data: bytes, fmt: str) -> str:
    """git's object id of a blob with these bytes."""
    if fmt not in OBJECT_FORMATS:
        raise HeadBindingError(f"unsupported git object format: {fmt!r}")
    # SHA-1 here is git's object id (second-preimage resistance against
    # committed blobs only), not a security digest of our own choosing.
    return hashlib.new(fmt, b"blob %d\0" % len(data) + data).hexdigest()  # nosec B324 -- git object id


def _rel(path, repo_root) -> str:
    return Path(path).resolve().relative_to(Path(repo_root).resolve()).as_posix()


def map_arcname(arcname: str, agent_cfg: dict, repo_root, *, local_dev: bool = False):
    """Return the repo path for `arcname`, None to skip it, or raise KeyError
    for an unmapped arcname."""
    for rule, pattern in ARCNAME_RULES:
        if rule == "skip":
            if pattern.match(arcname):
                return None
        elif rule == "root_file":
            for src, root_arcname in agent_cfg.get("root_files", []):
                if arcname == root_arcname:
                    return _rel(src, repo_root)
            if agent_cfg.get("registry_signature") and arcname == REGISTRY_SIGNATURE_ARCNAME:
                return REGISTRY_SIGNATURE_ARCNAME if local_dev else REGISTRY_KMS_SIGNATURE_PATH
        elif rule == "lambdas":
            m = pattern.match(arcname)
            if m:
                for extra_dir in agent_cfg.get("extra_dirs", []):
                    if Path(extra_dir).name == m.group(1):
                        return f"{_rel(extra_dir, repo_root)}/{m.group(2)}"
        elif rule == "package":
            m = pattern.match(arcname)
            if m:
                for package_dir in agent_cfg.get("packages", []):
                    if Path(package_dir).name == m.group(1):
                        return f"{_rel(package_dir, repo_root)}/{m.group(2)}"
        elif rule == "code_dir":
            m = pattern.match(arcname)
            if m:
                return f"{_rel(agent_cfg['code_dir'], repo_root)}/{m.group(1)}"
    raise KeyError(arcname)


def check_bundle_at_head(zip_path, agent_cfg, *, git_path, repo_root, local_dev: bool = False,
                         git=None, tree=None, fmt=None) -> list:
    """Return the offending arcnames of `zip_path` (empty list = every packaged
    source equals its HEAD blob).

    An entry is offending when it is unmapped, absent from HEAD, not a regular
    blob (symlink 120000 / submodule 160000), or its bytes' blob id differs
    from the HEAD tree's oid. `tree`/`fmt` may be passed in so a caller
    checking several zips runs ls-tree / show-object-format once."""
    git = git or default_git_runner(repo_root)
    if fmt is None:
        fmt = object_format(git, git_path)
    if tree is None:
        tree = head_tree(git, git_path)
    offending = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            arcname = info.filename
            try:
                repo_path = map_arcname(arcname, agent_cfg, repo_root, local_dev=local_dev)
            except (KeyError, ValueError):
                offending.append(arcname)
                continue
            if repo_path is None:
                continue
            entry = tree.get(repo_path)
            if entry is None or entry[0] not in ALLOWED_BLOB_MODES:
                offending.append(arcname)
                continue
            if blob_id(zf.read(info), fmt) != entry[1]:
                offending.append(arcname)
    return offending
