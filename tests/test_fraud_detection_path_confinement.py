"""
Test: Detection Agent — fraud_detection.py path confinement.

Three compounding defects in the pre-fix _resolve_confined_path:
1. The .json/.jsonl suffix was checked on the RAW caller-supplied path,
   before os.path.realpath() — a symlink literally named "evil.json"
   pointing anywhere passed the suffix check by name alone.
2. The size guard called os.path.getsize(resolved) and then reopened the
   same path separately — a TOCTOU window.
3. ALLOWED_TXN_DIR was read from the environment with no validation, so
   ALLOWED_TXN_DIR=/ removed containment entirely.

These tests exercise the module's functions directly (reimporting with a
patched ALLOWED_TXN_DIR where needed) rather than just inspecting source
text.
"""
import importlib
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.detection_agent.fraud_detection as fd


class TestSuffixCheckedAfterRealpath:
    def test_symlink_named_json_pointing_outside_allowed_dir_is_rejected(self, tmp_path, monkeypatch):
        """A symlink named *.json whose target resolves outside
        ALLOWED_TXN_DIR must be rejected — the suffix check alone (on the
        raw, unresolved name) must not be enough to pass containment."""
        allowed_dir = tmp_path / "data"
        allowed_dir.mkdir()
        outside_target = tmp_path / "outside" / "secret.txt"
        outside_target.parent.mkdir()
        outside_target.write_text('{"not": "a transaction file, could be anything"}', encoding="utf-8")

        evil_symlink = allowed_dir / "evil.json"
        evil_symlink.symlink_to(outside_target)

        monkeypatch.setattr(fd, "ALLOWED_TXN_DIR", str(allowed_dir.resolve()))

        with pytest.raises(ValueError):
            fd._resolve_confined_path(str(evil_symlink))

    def test_symlink_target_without_json_suffix_is_rejected_even_if_name_has_it(self, tmp_path, monkeypatch):
        """A symlink named foo.json pointing at a file with no .json/.jsonl
        suffix (e.g. a renamed binary) must be rejected — checking the
        suffix on the resolved path, not the caller-supplied name, is the
        actual fix."""
        allowed_dir = tmp_path / "data"
        allowed_dir.mkdir()
        target = allowed_dir / "real_data.txt"
        target.write_text("not actually json-suffixed", encoding="utf-8")
        symlink = allowed_dir / "looks_like.json"
        symlink.symlink_to(target)

        monkeypatch.setattr(fd, "ALLOWED_TXN_DIR", str(allowed_dir.resolve()))

        with pytest.raises(ValueError):
            fd._resolve_confined_path(str(symlink))

    def test_ordinary_file_inside_allowed_dir_is_accepted(self, tmp_path, monkeypatch):
        allowed_dir = tmp_path / "data"
        allowed_dir.mkdir()
        target = allowed_dir / "transactions.json"
        target.write_text('{"a": 1}', encoding="utf-8")

        monkeypatch.setattr(fd, "ALLOWED_TXN_DIR", str(allowed_dir.resolve()))

        resolved = fd._resolve_confined_path(str(target))
        assert resolved == str(target.resolve())


class TestLoadTransactionsNoFollowAndFstat:
    def test_load_transactions_opens_with_o_nofollow(self, tmp_path, monkeypatch):
        """load_transactions must open the resolved path with O_NOFOLLOW —
        this is the TOCTOU defense: if the resolved path is replaced with a
        symlink in the window between os.path.realpath() and open() (the
        exact race the O_NOFOLLOW open closes), the open must fail rather than
        silently follow it. os.path.realpath() legitimately dereferences
        an already-existing symlink as part of confinement resolution
        (that's not the bug) — O_NOFOLLOW guards the open() call itself
        against a swap that happens after resolution."""
        allowed_dir = tmp_path / "data"
        allowed_dir.mkdir()
        f = allowed_dir / "transactions.jsonl"
        f.write_text('{"sender_id": "a", "receiver_id": "b", "amount": 1}\n', encoding="utf-8")
        monkeypatch.setattr(fd, "ALLOWED_TXN_DIR", str(allowed_dir.resolve()))

        captured_flags = {}
        real_open = os.open

        def spying_open(path, flags, *a, **k):
            captured_flags["flags"] = flags
            return real_open(path, flags, *a, **k)

        monkeypatch.setattr(fd.os, "open", spying_open)

        fd.load_transactions(str(f))
        assert captured_flags["flags"] & os.O_NOFOLLOW

    def test_load_transactions_rejects_symlink_swapped_in_after_resolution(self, tmp_path, monkeypatch):
        """Simulates the TOCTOU outcome directly: _resolve_confined_path
        returns a path that, by the time load_transactions opens it, is a
        symlink (e.g. swapped in by a concurrent attacker between resolve
        and open). O_NOFOLLOW must cause this open to fail rather than
        transparently follow the symlink and read whatever it points to."""
        allowed_dir = tmp_path / "data"
        allowed_dir.mkdir()
        decoy_target = tmp_path / "decoy.jsonl"
        decoy_target.write_text('{"sender_id": "x", "receiver_id": "y", "amount": 999}\n', encoding="utf-8")

        resolved_path = allowed_dir / "transactions.jsonl"
        # At the moment load_transactions actually opens this path, it is a
        # symlink — not the plain file _resolve_confined_path's realpath()
        # check believed it to be.
        resolved_path.symlink_to(decoy_target)

        monkeypatch.setattr(fd, "ALLOWED_TXN_DIR", str(allowed_dir.resolve()))
        monkeypatch.setattr(fd, "_resolve_confined_path", lambda filepath: str(resolved_path))

        with pytest.raises(OSError):
            fd.load_transactions(str(resolved_path))

    def test_load_transactions_reads_ordinary_file(self, tmp_path, monkeypatch):
        allowed_dir = tmp_path / "data"
        allowed_dir.mkdir()
        f = allowed_dir / "transactions.jsonl"
        f.write_text(
            '{"sender_id": "a", "receiver_id": "b", "amount": 1}\n'
            '{"sender_id": "b", "receiver_id": "c", "amount": 2}\n', encoding="utf-8"
        )
        monkeypatch.setattr(fd, "ALLOWED_TXN_DIR", str(allowed_dir.resolve()))

        txns = fd.load_transactions(str(f))
        assert len(txns) == 2

    def test_load_transactions_enforces_size_cap_via_fstat(self, tmp_path, monkeypatch):
        """The size check now happens via os.fstat() on the single opened
        fd, not a separate getsize()-then-reopen — oversized files are
        still rejected."""
        allowed_dir = tmp_path / "data"
        allowed_dir.mkdir()
        f = allowed_dir / "big.jsonl"
        f.write_text('{"sender_id": "a", "receiver_id": "b", "amount": 1}\n' * 1000, encoding="utf-8")

        monkeypatch.setattr(fd, "ALLOWED_TXN_DIR", str(allowed_dir.resolve()))
        monkeypatch.setattr(fd, "MAX_TXN_FILE_BYTES", 10)  # force a cap failure

        with pytest.raises(ValueError):
            fd.load_transactions(str(f))


class TestAllowedTxnDirValidation:
    def test_root_env_override_is_rejected(self):
        """ALLOWED_TXN_DIR=/ must be rejected at validation time, not
        silently accepted as a containment boundary of nothing."""
        with pytest.raises(ValueError):
            fd._validate_allowed_txn_dir("/")

    def test_unrelated_absolute_path_is_rejected(self):
        """An env override pointing at a directory outside the project root
        entirely (e.g. /etc) must be rejected."""
        with pytest.raises(ValueError):
            fd._validate_allowed_txn_dir("/etc")

    def test_project_root_itself_is_accepted(self):
        """The project's own data/ directory (the default) validates fine."""
        resolved = fd._validate_allowed_txn_dir(fd._DEFAULT_TXN_DIR)
        assert resolved == os.path.realpath(fd._DEFAULT_TXN_DIR)
