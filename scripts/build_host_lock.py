#!/usr/bin/env python3
"""
Write a hash-locked requirements file from an exactly pinned one.

Dev tool, not run by the build. It reads only public PyPI JSON metadata
(https://pypi.org/pypi/<name>/<version>/json; read-only GETs over HTTPS, no
redirects off pypi.org, no project data sent) and downloads no package files.

  --target host   (requirements*.lock) every published file of each pinned
                  version is listed, so one lock installs on macOS and Linux,
                  x86_64 and arm64 (pip accepts any listed hash). Markers are
                  evaluated for darwin + linux, CPython 3.13.
  --target agent  (agentcore/<agent>/requirements.lock) only the wheels a
                  binary-only install for linux aarch64 / cp313 can pick
                  (manylinux2014 .. manylinux_2_28, or pure-Python wheels).

The closure is resolved from each pin's requires_dist. A transitive version
is taken from the local environment when it is installed and satisfies every
specifier (the pins come from the working venv); otherwise the highest final
release that satisfies them is chosen from the PyPI release list. Conflicts
abort. Usage:

    python scripts/build_host_lock.py --requirements requirements.txt --output requirements.lock
    python scripts/build_host_lock.py --target agent \\
        --requirements agentcore/detection_agent/requirements.txt \\
        --output agentcore/detection_agent/requirements.lock
"""
import argparse
import importlib.metadata
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

PYPI_HOST = "pypi.org"
TIMEOUT_SECONDS = 30
PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)(\[[a-z0-9_,-]+\])?==([0-9][A-Za-z0-9.+!-]*)$")

_BASE_ENV = {"implementation_name": "cpython", "platform_python_implementation": "CPython",
             "python_version": "3.13", "python_full_version": "3.13.7", "implementation_version": "3.13.7",
             "platform_release": "", "platform_version": ""}
HOST_ENVS = [
    dict(_BASE_ENV, os_name="posix", sys_platform="darwin", platform_system="Darwin", platform_machine="arm64"),
    dict(_BASE_ENV, os_name="posix", sys_platform="darwin", platform_system="Darwin", platform_machine="x86_64"),
    dict(_BASE_ENV, os_name="posix", sys_platform="linux", platform_system="Linux", platform_machine="x86_64"),
    dict(_BASE_ENV, os_name="posix", sys_platform="linux", platform_system="Linux", platform_machine="aarch64"),
]
AGENT_ENVS = [HOST_ENVS[3]]
AGENT_MAX_GLIBC_MINOR = 28


class LockError(Exception):
    pass


class _PypiOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname != PYPI_HOST:
            raise LockError(f"refusing redirect to {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_PypiOnlyRedirects)
_CACHE = {}


def _get_json(path: str) -> dict:
    url = f"https://{PYPI_HOST}/pypi/{path}/json"
    if url not in _CACHE:
        try:
            with _OPENER.open(urllib.request.Request(url, headers={"Accept": "application/json"}),
                              timeout=TIMEOUT_SECONDS) as response:  # nosec B310 -- fixed https://pypi.org URL
                _CACHE[url] = json.load(response)
        except urllib.error.URLError as exc:
            raise LockError(f"cannot read {url} ({exc})") from exc
    return _CACHE[url]


def read_pins(path: str) -> list:
    pins = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            m = PIN_RE.match(line)
            if not m:
                raise LockError(f"{path}: not an exact pin: {line!r}")
            extras = set(filter(None, (m.group(2) or "[]")[1:-1].split(",")))
            pins.append((m.group(1), m.group(3), extras))
    return pins


def _agent_wheel_ok(filename: str) -> bool:
    if not filename.endswith(".whl"):
        return False
    _name, _ver, _build, tags = parse_wheel_filename(filename)
    for tag in tags:
        if tag.interpreter not in ("cp313", "py3", "py2.py3") and not tag.interpreter.startswith("py3"):
            continue
        if tag.abi not in ("cp313", "abi3", "none"):
            continue
        if tag.platform == "any" or tag.platform == "manylinux2014_aarch64":
            return True
        m = re.fullmatch(r"manylinux_2_(\d+)_aarch64", tag.platform)
        if m and int(m.group(1)) <= AGENT_MAX_GLIBC_MINOR:
            return True
    return False


def _files(name: str, version: str, target: str) -> list:
    data = _get_json(f"{name}/{version}")
    hashes = []
    for entry in data.get("urls", []):
        if entry.get("yanked"):
            continue
        if target == "agent" and not _agent_wheel_ok(entry["filename"]):
            continue
        digest = entry.get("digests", {}).get("sha256", "")
        if re.fullmatch(r"[0-9a-f]{64}", digest):
            hashes.append(digest)
    if not hashes:
        raise LockError(f"{name}=={version}: no {'linux aarch64 cp313 wheel' if target == 'agent' else 'file'} published")
    return sorted(set(hashes))


def _applies(req: Requirement, extras: set, envs: list) -> bool:
    if req.marker is None:
        return True
    for env in envs:
        for extra in (extras or {""}):
            if req.marker.evaluate(dict(env, extra=extra)):
                return True
    return False


def _pick_version(name: str, spec: SpecifierSet, target: str) -> str:
    try:
        installed = importlib.metadata.version(name)
        if spec.contains(installed, prereleases=False):
            return installed
    except importlib.metadata.PackageNotFoundError:
        pass
    releases = _get_json(name).get("releases", {})
    for candidate in sorted(releases, key=Version, reverse=True):
        v = Version(candidate)
        if v.is_prerelease or not spec.contains(candidate):  # nosemgrep: is-function-without-parentheses -- packaging.version.Version.is_prerelease is a property, not a method
            continue
        files = [f for f in releases[candidate] if not f.get("yanked")]
        if target == "agent" and not any(_agent_wheel_ok(f["filename"]) for f in files):
            continue
        if files:
            return candidate
    raise LockError(f"no release of {name} satisfies {spec}")


def resolve(pins: list, target: str) -> dict:
    envs = AGENT_ENVS if target == "agent" else HOST_ENVS
    chosen = {}          # canonical name -> (display name, version)
    specs = {}           # canonical name -> SpecifierSet
    queue = []
    for name, version, extras in pins:
        key = canonicalize_name(name)
        chosen[key] = (name, version)
        specs[key] = SpecifierSet(f"=={version}")
        queue.append((key, extras))
    seen = set()
    while queue:
        key, extras = queue.pop(0)
        if (key, frozenset(extras)) in seen:
            continue
        seen.add((key, frozenset(extras)))
        name, version = chosen[key]
        info = _get_json(f"{name}/{version}").get("info", {})
        for raw in info.get("requires_dist") or []:
            req = Requirement(raw)
            if not _applies(req, extras, envs):
                continue
            dep = canonicalize_name(req.name)
            specs[dep] = specs.get(dep, SpecifierSet()) & req.specifier
            if dep in chosen:
                if not specs[dep].contains(chosen[dep][1], prereleases=True):
                    raise LockError(f"conflict: {dep}=={chosen[dep][1]} vs {specs[dep]}")
            else:
                chosen[dep] = (req.name, _pick_version(req.name, specs[dep], target))
            queue.append((dep, set(req.extras)))
    return chosen


def render(chosen: dict, source: str, target: str) -> str:
    lines = [f"# Generated by scripts/build_host_lock.py from {source} (target: {target}).",
             "# Do not edit by hand. Install with: pip install --require-hashes -r <this file>"]
    if target == "agent":
        lines.append("# Wheels for linux aarch64 / CPython 3.13, binary-only "
                     f"(manylinux2014 .. manylinux_2_{AGENT_MAX_GLIBC_MINOR}).")
    for key in sorted(chosen):
        name, version = chosen[key]
        hashes = _files(name, version, target)
        lines.append(f"{key}=={version} \\")
        lines.extend(f"    --hash=sha256:{h}" + (" \\" if i < len(hashes) - 1 else "")
                     for i, h in enumerate(hashes))
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build a hash-locked requirements file from exact pins")
    parser.add_argument("--requirements", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--target", choices=("host", "agent"), default="host")
    args = parser.parse_args(argv)
    try:
        chosen = resolve(read_pins(args.requirements), args.target)
        text = render(chosen, args.requirements, args.target)
    except LockError as exc:
        print(f"✗ {exc}")
        return 1
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"✓ wrote {args.output} ({len(chosen)} packages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
