#!/usr/bin/env python3
"""
Verify that every jump-to-code link in the docs still resolves.

Guards the FIVE_DS_CODE_MAP.md (and any other doc) against line drift: when a
link points at `../path/to/file.py#L146`, this checks that the file exists, the
line exists, and — when the link text names a symbol in backticks — that the
symbol actually appears on or very near that line. Fails loudly (exit 1) with a
per-link report so a stale anchor is caught before a demo, not during it.

Usage:
    python scripts/verify_doc_links.py                 # checks docs/*.md
    python scripts/verify_doc_links.py docs/FIVE_DS_CODE_MAP.md ...

Only links that contain a `#L<n>` line anchor are checked. Plain file links
(no line anchor) are validated for file existence only. External http(s) links
are ignored.
"""
import os
import re
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")

# Matches markdown links: [label](target)
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
# Extracts a symbol from link text: last `backticked` token, stripped of () and args.
SYMBOL_RE = re.compile(r"`([^`]+)`")
# How many lines above the anchor a symbol may appear (decorators/blank tolerance).
LINE_TOLERANCE = 2


def iter_doc_files(args):
    if args:
        for a in args:
            yield a if os.path.isabs(a) else os.path.join(PROJECT_ROOT, a)
        return
    for name in sorted(os.listdir(DOCS_DIR)):
        if name.endswith(".md"):
            yield os.path.join(DOCS_DIR, name)


def extract_symbol(label: str) -> str:
    """Pull a likely symbol name from the link label (last backticked chunk)."""
    matches = SYMBOL_RE.findall(label)
    if not matches:
        return ""
    token = matches[-1].strip()
    # "ClassName → method()" or "file.py → symbol" → take the part after an arrow.
    if "→" in token:
        token = token.split("→")[-1].strip()
    # Strip call parens and args: "validate_model()" -> "validate_model"
    token = token.split("(")[0].strip()
    # Ignore bare filenames (contain a dot + known ext) — nothing to grep for.
    if re.search(r"\.(py|ts|tsx|js|json|md|sh)$", token):
        return ""
    return token


def check_link(doc_path: str, label: str, target: str):
    """Return (ok, message) for a single link."""
    if target.startswith(("http://", "https://", "#", "mailto:")):
        return True, None  # external / in-page anchor — skip

    # Split off a #Lnn line anchor if present.
    line_no = None
    m = re.search(r"#L(\d+)$", target)
    path_part = target
    if m:
        line_no = int(m.group(1))
        path_part = target[: m.start()]

    resolved = os.path.normpath(os.path.join(os.path.dirname(doc_path), path_part))

    if not os.path.exists(resolved):
        return False, f"file not found: {path_part}"

    if line_no is None:
        return True, None  # file-only link, exists — good enough

    with open(resolved, encoding="utf-8") as f:
        lines = f.readlines()

    if line_no > len(lines):
        return False, f"{path_part}: line {line_no} beyond EOF ({len(lines)} lines)"

    symbol = extract_symbol(label)
    if not symbol:
        return True, None  # no symbol to verify; line exists

    # Check the symbol appears on the anchored line, or within a small window
    # above it (tolerates decorators / a blank line before a def).
    lo = max(0, line_no - 1 - LINE_TOLERANCE)
    hi = min(len(lines), line_no + LINE_TOLERANCE)
    window = "".join(lines[lo:hi])
    if symbol in window:
        return True, None

    # Symbol drifted — find where it actually is, to make the fix trivial.
    actual = [i + 1 for i, ln in enumerate(lines) if symbol in ln]
    hint = f" (found at line {actual[0]})" if actual else " (symbol not found in file)"
    return False, f"{path_part}#L{line_no}: '{symbol}' not on/near line {line_no}{hint}"


def main():
    args = sys.argv[1:]
    total = 0
    failures = []

    for doc_path in iter_doc_files(args):
        if not os.path.exists(doc_path):
            failures.append((doc_path, "", "doc file not found"))
            continue
        with open(doc_path, encoding="utf-8") as f:
            content = f.read()
        for label, target in LINK_RE.findall(content):
            # Only care about links into the code tree (relative paths).
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            total += 1
            ok, msg = check_link(doc_path, label, target)
            if not ok:
                failures.append((os.path.relpath(doc_path, PROJECT_ROOT), target, msg))

    print(f"Checked {total} code link(s) across docs.")
    if failures:
        print(f"\n{len(failures)} BROKEN link(s):")
        for doc, target, msg in failures:
            print(f"  [{doc}] {target}\n      -> {msg}")
        return 1
    print("All doc links resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
