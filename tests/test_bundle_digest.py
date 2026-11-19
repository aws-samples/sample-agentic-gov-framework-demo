"""
Test: governance_common.bundle_digest.

The digest depends only on (arcname, bytes) pairs: independent of zip entry
order, timestamps and compression; governance/ is excluded; any content or
name change alters it; duplicated arcnames are refused.
"""
import hashlib
import io
import zipfile

import pytest

from governance_common.bundle_digest import bundle_digest, entry_digests

FILES = {
    "main.py": b"print('hi')\n",
    "lambdas/compliance_agent/handler.py": b"def handler(e, c=None):\n    return {}\n",
    "governance_common/signing.py": b"X = 1\n",
    "lib/pkg/__init__.py": b"",
}


def _zip(entries, *, date=(2020, 1, 1, 0, 0, 0), compression=zipfile.ZIP_DEFLATED, dirs=()):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for d in dirs:
            zf.writestr(zipfile.ZipInfo(d, date_time=date), b"")
        for name, data in entries:
            zf.writestr(zipfile.ZipInfo(name, date_time=date), data, compress_type=compression)
    buf.seek(0)
    return buf


def test_order_timestamp_and_compression_independent():
    a = bundle_digest(_zip(list(FILES.items())))
    b = bundle_digest(_zip(list(reversed(FILES.items())), date=(2031, 6, 7, 8, 9, 10),
                           compression=zipfile.ZIP_STORED, dirs=("lib/",)))
    assert a == b


def test_matches_documented_formula():
    expected = "\n".join(f"{n}\t{hashlib.sha256(FILES[n]).hexdigest()}" for n in sorted(FILES))
    assert bundle_digest(_zip(list(FILES.items()))) == hashlib.sha256(expected.encode()).hexdigest()


def test_governance_prefix_excluded():
    base = bundle_digest(_zip(list(FILES.items())))
    with_artifact = bundle_digest(_zip(list(FILES.items()) + [
        ("governance/gate-artifact.json", b"{}"), ("governance/gate-artifact.json.sig", b"{}")]))
    assert base == with_artifact
    assert "governance/gate-artifact.json" not in entry_digests(_zip([("governance/gate-artifact.json", b"{}")]))


def test_content_or_name_change_alters_digest():
    base = bundle_digest(_zip(list(FILES.items())))
    changed = dict(FILES, **{"main.py": b"print('hj')\n"})
    assert bundle_digest(_zip(list(changed.items()))) != base
    renamed = {("x" + k if k == "main.py" else k): v for k, v in FILES.items()}
    assert bundle_digest(_zip(list(renamed.items()))) != base
    assert bundle_digest(_zip(list(FILES.items()) + [("extra.py", b"")])) != base


def test_duplicate_arcname_refused():
    with pytest.warns(UserWarning):  # zipfile warns on the duplicate write
        dup = _zip([("main.py", b"a"), ("main.py", b"b")])
    with pytest.raises(ValueError):
        bundle_digest(dup)


def test_accepts_a_path(tmp_path):
    path = tmp_path / "b.zip"
    path.write_bytes(_zip(list(FILES.items())).getvalue())
    assert bundle_digest(path) == bundle_digest(_zip(list(FILES.items())))
