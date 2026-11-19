"""
PAN filter — formal detection-spec compliance suite (PERMANENT regression).

This is the standing executable acceptance surface for the PAN filter's
detection model (the adversarial input class table below). It is deliberately
PARAMETRIZED over every row of that table and run
against all 3 duplicated copies of the module, so it guards this exact bypass
history — Unicode separators, ASCII separators, single/multi interleaved
letters, digit-padded interleaved letters, non-ASCII digits, real masking
(short and interior), scattered mask chars, unrelated-field masking, and the
timestamp false-positive residual — against every future pass. A new
adversarial input is NOT added here as a one-off test function; it is added
as a row in SPEC_ROWS so the parametrization carries it.

The current detection model changed three rows from the earlier detector: 3a
is now False (more than one bridged letter in the window), 6a is now True
(mask glyphs never suppress a Luhn-valid window) and 9a is now False (N1
datetime exemption). The full adversarial matrix lives in
tests/test_pan_filter_adversarial_matrix.py.

The "cross-field split with interleaved letter" test encodes a documented
residual: asserted here so a future change does not silently reverse it.
"""
import json
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.pan_filter.pan_filter as pan_filter_copy
import lambdas.detection_agent.pan_filter as detection_agent_pan_filter_copy
import lambdas.executor_agent.pan_filter.pan_filter as executor_agent_pan_filter_copy

_PAN_FILTER_MODULES = [
    pan_filter_copy,
    detection_agent_pan_filter_copy,
    executor_agent_pan_filter_copy,
]
_PAN_FILTER_MODULE_IDS = [
    "lambdas.pan_filter.pan_filter",
    "lambdas.detection_agent.pan_filter",
    "lambdas.executor_agent.pan_filter.pan_filter",
]

# The canonical Luhn-valid 16-digit test PAN used throughout the table.
_PAN = "4532015112830366"

# Arabic-Indic digits for _PAN (row 5): U+0660-U+0669.
_ARABIC_PAN = "".join(chr(0x0660 + int(d)) for d in _PAN)


# ---------------------------------------------------------------------------
# Adversarial input class table — one entry per row.
#
# Each entry is (row_id, text, expected_contains_full_pan, rule_reference).
# `text` is the exact input the row's Example column specifies; the test
# asserts contains_full_pan(text) == expected for every module copy.
# ---------------------------------------------------------------------------
SPEC_ROWS = [
    (
        "1_unicode_separator",
        "4532\u200b0151\u200b1283\u200b0366",
        True,
        "D4 — zero-width chars are FOLD; W1 finds the PAN (matrix B03)",
    ),
    (
        "2_ascii_separator",
        "4532-0151-1283-0366",
        True,
        "rule 5 — '-' is FOLD; W1 (matrix B02)",
    ),
    (
        "3_single_interleaved_letter",
        "4532a015112830366",
        True,
        "soft bridge — one letter inside the window (W1(a))",
    ),
    (
        "3a_multi_interleaved_letter",
        "4532a0151b1283c0366",
        False,
        "residual — three bridged letters inside every 16-digit window exceed W1(a)'s cap of one (matrix R3c)",
    ),
    (
        "4_digit_padded_interleaved_letter",
        "0000000000" + "4532a015112830366" + "0000000000",
        True,
        "W1 — padding outside the window cannot affect it (matrix B19)",
    ),
    (
        "4a_mixed_content_single_run",
        "4532a015112830366-7b8",
        True,
        "W1 — window [0,16) holds the PAN with one bridge (matrix B26)",
    ),
    (
        "5_non_ascii_decimal_digits",
        _ARABIC_PAN,
        True,
        "rule 1 (D1) — Arabic-Indic digits map to ASCII (matrix B05)",
    ),
    (
        "6_masked_pan_short_surviving_run",
        "4532-01**-****-0366",
        False,
        "B1 — 8 surviving digits, no 13-digit window (matrix F12)",
    ),
    (
        "6a_masked_pan_interior_run_S3",
        "4532015112xxxxxx830366",
        True,
        "mask glyphs fold and never suppress a Luhn-valid window (matrix B14)",
    ),
    (
        "7_scattered_isolated_mask_chars",
        "4532*0151*1283*0366",
        True,
        "rule 3 — '*' is a glyph FOLD; W1 (matrix B17)",
    ),
    (
        "8_unrelated_field_mask_other_field_pan",
        json.dumps({"note": "xxxxxx", "card": _PAN}),
        True,
        "W1 — no mask suppression anywhere; 'card' breaks before the PAN sub-run (matrix B24)",
    ),
    (
        "9_timestamp_general_case",
        "2026-01-01T00:00:00.000001",
        False,
        "N1 — whole-leaf datetime is exempt (matrix F02)",
    ),
    (
        "9a_timestamp_coincidental_luhn_residual",
        "2026-08-19T03:11:39.014082",
        False,
        "N1 — calendar-valid ISO-8601 datetime is exempt; no digits remain (matrix F01)",
    ),
]


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
@pytest.mark.parametrize(
    "row_id,text,expected,rule",
    SPEC_ROWS,
    ids=[row[0] for row in SPEC_ROWS],
)
def test_spec_table_row(mod, row_id, text, expected, rule):
    """Every row of the table, asserted against every module copy.
    `rule` names the rule(s) that derive the expected outcome."""
    assert mod.contains_full_pan(text) is expected, (
        f"spec row {row_id} ({rule}): expected contains_full_pan == {expected}"
    )


# ---------------------------------------------------------------------------
# Row 10 is a two-field transaction with per-field expectations, so it is
# parametrized separately (one leaf must NOT fuse across a multi-letter run,
# the other IS a cleartext PAN that must still be flagged).
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_spec_row_10_mixed_identifier_adjacent_to_pan(mod):
    """Row 10: `acc` leaf has a 3-char LETTER run → never bridged,
    excluded from reassembly, no candidate of its own long enough to
    matter; `card` leaf is an independent cleartext PAN → flagged."""
    # acc leaf alone is not a PAN.
    assert mod.contains_full_pan("acc-10293847") is False
    # card leaf alone is a PAN.
    assert mod.contains_full_pan(_PAN) is True
    # Whole transaction: flagged because of the cleartext card field.
    txns = [{"txn_id": "row10", "acc": "acc-10293847", "card": _PAN}]
    clean, rejected, details = mod.filter_transactions(txns)
    assert rejected == 1
    assert len(clean) == 0


# ---------------------------------------------------------------------------
# Accepted behavior-change rows relative to the earlier detector.
# These are asserted here (in addition to their table rows above) with an
# explicit "accepted residual / known limitation, not a regression" label so
# a future pass that re-tightens the filter sees the deliberate tradeoff
# stated here rather than treating these outcomes as fresh bugs.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_iso_timestamp_exempt(mod):
    """N1 (replaces the earlier row 9a accepted residual): a
    calendar-valid ISO-8601 datetime is exempt, so this timestamp is not
    PAN-shaped and a transaction carrying it is not rejected."""
    assert mod.contains_full_pan("2026-08-19T03:11:39.014082") is False
    txns = [{"txn_id": "ts", "timestamp": "2026-08-19T03:11:39.014082", "amount": 289.45}]
    clean, rejected, details = mod.filter_transactions(txns)
    assert rejected == 0


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_known_limitation_cross_field_split_with_interleaved_letter_not_caught(mod):
    """KNOWN LIMITATION — documented residual (matrix row R1a), NOT a
    regression: a cross-field fragment that contains an interior letter or
    interior mask glyph is not reassembled. X2 breaks fragment runs at every
    LETTER and glyph, so `4532a0151` contributes `4532` and `0151` and
    `1283x0366` contributes `1283` and `0366`; no exact chain concatenation
    is the PAN. Closing it means bridging letters inside fragment runs, which
    raises schema false positives from about 1% to about 7%."""
    txns = [{"txn_id": "split-letter", "a": "4532a0151", "b": "1283x0366"}]
    clean, rejected, details = mod.filter_transactions(txns)
    assert rejected == 0
    assert len(clean) == 1


# ---------------------------------------------------------------------------
# Structural guarantees required beyond the row table — asserted
# directly so a copy-specific regression in any of the 3 modules is caught.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_matrix_z06_unrelated_digit_fields_not_rejected(mod):
    """Matrix row Z06 (there is no whole-JSON scan): three unrelated 8-digit fields
    chain under X3, but no exact X4 concatenation passes the MII gate, so
    the transaction is not rejected."""
    txns = [{"x": "12345678", "y": "87654321", "z": "11112222"}]
    clean, rejected, details = mod.filter_transactions(txns)
    assert rejected == 0
    assert len(clean) == 1


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_cross_field_split_without_letters_still_caught(mod):
    """A cleartext PAN split across two fields with NO interleaved
    letters (each leaf a clean digit run) still reassembles and is caught
    (this is the capability the known limitation does NOT remove)."""
    txns = [{"txn_id": "split", "pan_a": "45320151", "pan_b": "12830366"}]
    clean, rejected, details = mod.filter_transactions(txns)
    assert rejected == 1
    assert len(clean) == 0
