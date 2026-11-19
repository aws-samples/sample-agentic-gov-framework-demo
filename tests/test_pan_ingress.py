"""
Test: PAN Ingress Filter — all 6 evasion variants must be caught BEFORE graph processing.
"""
import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from lambdas.detection_agent.pan_filter import contains_full_pan, filter_transactions

import lambdas.pan_filter.pan_filter as pan_filter_copy
import lambdas.detection_agent.pan_filter as detection_agent_pan_filter_copy
import lambdas.executor_agent.pan_filter.pan_filter as executor_agent_pan_filter_copy


class TestPANIngress:
    """PCI-DSS v4.0 section 3.4 compliance — PAN detection at ingress."""

    # Luhn-valid test PAN: 4532015112830366
    VALID_PAN = "4532015112830366"

    def test_plain_16_digit(self):
        """Variant 1: Plain 16-digit number."""
        assert contains_full_pan("4532015112830366")

    def test_dash_separated(self):
        """Variant 2: Dash-separated."""
        assert contains_full_pan("4532-0151-1283-0366")

    def test_space_separated(self):
        """Variant 3: Space-separated."""
        assert contains_full_pan("4532 0151 1283 0366")

    def test_zero_width_injection(self):
        """Variant 4: Zero-width character injection."""
        assert contains_full_pan("4532\u200b0151\u200b1283\u200b0366")

    def test_mixed_separators(self):
        """Variant 5: Mixed separator styles."""
        assert contains_full_pan("4532-0151 1283-0366")

    def test_unicode_fullwidth(self):
        """Variant 6: Unicode full-width digits."""
        # Full-width digits for 4532015112830366
        fullwidth = "\uff14\uff15\uff13\uff12\uff10\uff11\uff15\uff11\uff11\uff12\uff18\uff13\uff10\uff13\uff16\uff16"
        assert contains_full_pan(fullwidth)

    def test_amex_15_digit(self):
        """AMEX 15-digit PAN (Luhn-valid: 371449635398431)."""
        assert contains_full_pan("371449635398431")

    def test_masked_pan_not_caught(self):
        """Masked PAN with stars should NOT be flagged."""
        assert not contains_full_pan("4532-01**-****-0366")

    def test_masked_pan_x_not_caught(self):
        """Masked PAN with x should NOT be flagged."""
        assert not contains_full_pan("4532xxxxxxxx0366")

    def test_random_number_without_any_luhn_valid_substring_not_caught(self):
        """A digit run with no Luhn-valid 13-19 digit substring anywhere in
        it should NOT be caught. Unlike a single whole-string Luhn check,
        the sliding-window scan (needed to catch digit-padded PANs, see
        test_digit_padding_both_sides) tests every substring, so this fixture
        is chosen to have no Luhn-valid substring at any length 13-19."""
        assert not contains_full_pan("1043321819600133")

    def test_empty_string(self):
        """Empty string returns False."""
        assert not contains_full_pan("")

    def test_none_input(self):
        """None input returns False."""
        assert not contains_full_pan(None)

    def test_filter_batch_removes_pan(self):
        """Batch filter correctly removes transactions with PAN."""
        txns = [
            {"txn_id": "clean-1", "sender_id": "a", "receiver_id": "b", "amount": 100},
            {"txn_id": "dirty-1", "card": "4532015112830366", "amount": 500},
            {"txn_id": "clean-2", "sender_id": "c", "receiver_id": "d", "amount": 200},
        ]
        clean, rejected, details = filter_transactions(txns)
        assert len(clean) == 2
        assert rejected == 1
        # rejection_details carries a non-reversible, keyed reference, never
        # the raw txn_id — the id field itself may carry the
        # PAN that triggered the rejection. txn_ref is now a
        # full 64-hex-char HMAC-SHA256 digest, not a truncated unsalted
        # SHA-256 — see TestTxnRefHmac below for the dedicated regression
        # coverage on that property.
        assert "txn_id" not in details[0]
        assert len(details[0]["txn_ref"]) == 64

    def test_pan_in_nested_json(self):
        """PAN embedded in nested JSON structure is caught."""
        import json
        data = {"transaction": {"card_number": "4532015112830366"}}
        assert contains_full_pan(json.dumps(data))

    # ------------------------------------------------------------------
    # Bypass regression cases
    # ------------------------------------------------------------------

    def test_soft_hyphen_separator(self):
        """Soft hyphen (U+00AD) used to break up the PAN must still be caught."""
        assert contains_full_pan("4532\u00ad0151\u00ad1283\u00ad0366")

    def test_word_joiner_separator(self):
        """Word joiner (U+2060, invisible) used to break up the PAN must still be caught."""
        assert contains_full_pan("4532\u20600151\u20601283\u20600366")

    def test_unicode_hyphen_u2010(self):
        """Unicode hyphen U+2010 must fold like ASCII '-'."""
        assert contains_full_pan("4532\u20100151\u20101283\u20100366")

    def test_unicode_hyphen_u2011(self):
        """Unicode non-breaking hyphen U+2011 must fold like ASCII '-'."""
        assert contains_full_pan("4532\u20110151\u20111283\u20110366")

    def test_dot_separated(self):
        """Dot-separated PAN must be caught."""
        assert contains_full_pan("4532.0151.1283.0366")

    def test_underscore_separated(self):
        """Underscore-separated PAN must be caught."""
        assert contains_full_pan("4532_0151_1283_0366")

    def test_digit_padding_both_sides(self):
        """A Luhn-valid PAN padded with extra digits on both sides must not
        escape detection via the old over-anchored, no-sliding-window regex."""
        assert contains_full_pan("0000" + self.VALID_PAN + "0000")

    def test_digit_padding_prefix_only(self):
        """A PAN with just two extra leading digits must still be caught."""
        assert contains_full_pan("12" + self.VALID_PAN)

    def test_cross_field_split(self):
        """A PAN deliberately split across two separate transaction fields
        with no separator in either field must be reassembled and caught by
        filter_transactions (the whole-JSON scan alone cannot reconnect
        fields separated by JSON punctuation)."""
        txns = [{"txn_id": "split-1", "pan_a": "45320151", "pan_b": "12830366"}]
        clean, rejected, details = filter_transactions(txns)
        assert rejected == 1
        assert len(clean) == 0
        assert len(details[0]["txn_ref"]) == 64

    def test_cross_field_split_not_falsely_triggered_by_unrelated_fields(self):
        """Ordinary numeric-looking fields (account ids, amounts) must not be
        fused together into a false-positive PAN match.

        The timestamp field is not part of this fixture (it was dropped
        earlier). Under N1 the literal
        ``2026-08-19T03:11:39.014082`` is now exempt and not flagged; see
        test_pan_filter_spec_compliance.test_iso_timestamp_exempt. The
        acc/amount fields below produce no false positive (matrix row Z01)."""
        txns = [{
            "txn_id": "clean-1",
            "sender_id": "acc-10293847",
            "receiver_id": "acc-56473829",
            "amount": 289.45,
        }]
        clean, rejected, details = filter_transactions(txns)
        assert rejected == 0
        assert len(clean) == 1

    # ------------------------------------------------------------------
    # Plain-separator bypass regression cases
    #
    # The prior remediation folded away dash/space/dot/
    # underscore separators and Cf format characters, but every other
    # separator still emitted a run break (NUL), so a PAN split with any
    # of these characters never reassembled into a detectable digit run.
    # ------------------------------------------------------------------

    def test_comma_separated(self):
        """Comma-separated PAN must be caught."""
        assert contains_full_pan("4532,0151,1283,0366")

    def test_slash_separated(self):
        """Slash-separated PAN must be caught."""
        assert contains_full_pan("4532/0151/1283/0366")

    def test_pipe_separated(self):
        """Pipe-separated PAN must be caught."""
        assert contains_full_pan("4532|0151|1283|0366")

    def test_colon_separated(self):
        """Colon-separated PAN must be caught."""
        assert contains_full_pan("4532:0151:1283:0366")

    def test_plus_separated(self):
        """Plus-sign-separated PAN must be caught."""
        assert contains_full_pan("4532+0151+1283+0366")

    def test_newline_separated(self):
        """Newline-separated PAN must be caught."""
        assert contains_full_pan("4532\n0151\n1283\n0366")

    def test_carriage_return_separated(self):
        """Carriage-return-separated PAN must be caught."""
        assert contains_full_pan("4532\r0151\r1283\r0366")

    def test_tab_separated(self):
        """Tab-separated PAN must be caught."""
        assert contains_full_pan("4532\t0151\t1283\t0366")

    def test_semicolon_separated(self):
        """Semicolon-separated PAN must be caught (general punctuation not
        previously on the fold allowlist)."""
        assert contains_full_pan("4532;0151;1283;0366")

    def test_parenthesis_separated(self):
        """Parenthesis-wrapped groups must still fold into one digit run."""
        assert contains_full_pan("(4532)(0151)(1283)(0366)")

    def test_mixed_new_separators(self):
        """A mix of the newly-folded separators must still be caught."""
        assert contains_full_pan("4532,0151/1283|0366")

    def test_comma_split_transaction_field(self):
        """End-to-end: a transaction whose card field uses comma separators
        (the exact original reproduction) must be rejected by
        filter_transactions, not just by contains_full_pan directly."""
        txns = [{"txn_id": "comma-1", "card": "4532,0151,1283,0366", "amount": 500}]
        clean, rejected, details = filter_transactions(txns)
        assert rejected == 1
        assert len(clean) == 0

    def test_masked_pan_with_star_still_not_caught_after_fold_widening(self):
        """Widening the fold set to close the separator bypass must not
        erode the masking protection: '*' stays an explicit run-break
        character, not a folding one."""
        assert not contains_full_pan("4532,01**,****,0366")

    def test_masked_pan_with_letter_x_still_not_caught_after_fold_widening(self):
        """Same as above for the letter-based mask marker 'x'."""
        assert not contains_full_pan("4532,xxxx,xxxx,0366")

    # ------------------------------------------------------------------
    # Non-ASCII Unicode digit crash
    #
    # str.isdigit() is True for non-ASCII Unicode "No"-category digits
    # (e.g. U+1369 ETHIOPIC DIGIT ONE) that have no ASCII NFKC
    # decomposition. Before the fix, these reached int(ch) in _luhn_valid
    # and raised an unhandled ValueError, aborting the whole batch (DoS).
    # ------------------------------------------------------------------

    def test_ethiopic_digit_does_not_crash(self):
        """A standalone Ethiopic digit must not raise — it's simply not a
        PAN (no ASCII digit run to scan)."""
        assert contains_full_pan("\u1369") is False

    def test_ethiopic_digit_mixed_with_real_pan_does_not_crash(self):
        """An Ethiopic digit adjacent to a real PAN must not abort the scan
        — the PAN is still caught, and the non-ASCII digit is simply
        dropped (treated like any other non-digit, non-letter character)
        rather than reaching int() and raising ValueError."""
        assert contains_full_pan("4532015112830366\u1369")

    def test_ethiopic_digit_run_does_not_crash_luhn(self):
        """A run composed entirely of Ethiopic digits must not raise inside
        _luhn_valid (the original DoS guard).

        BEHAVIOR CHANGE (rule D1): under the current detection model,
        non-ASCII decimal digits are now NORMALIZED to their
        ASCII value via unicodedata.digit and PARTICIPATE in the digit run
        — they are no longer silently dropped (dropping them was itself a
        bypass). So the right assertion is no longer "a non-ASCII
        digit run is always False"; it is "it is evaluated like the
        equivalent ASCII run, without crashing". This fixture uses an
        Ethiopic-digit run whose ASCII-normalized form (``6761996814393295``)
        has no Luhn-valid 13-19-digit window, so it is correctly NOT flagged
        — the same way the ASCII fixture ``1043321819600133`` is not — while
        proving the normalization path does not raise. See
        test_pan_filter_spec_compliance row 5 for the positive case (a
        non-ASCII-digit PAN that IS flagged)."""
        # Ethiopic digits for 6761996814393295 (Ethiopic has no zero; this
        # value is all 1-9 and has no Luhn-valid substring at any length).
        ethiopic_digits = "\u136e\u136f\u136e\u1369\u1371\u1371\u136e\u1370\u1369\u136c\u136b\u1371\u136b\u136a\u1371\u136d"
        assert contains_full_pan(ethiopic_digits) is False

    def test_filter_batch_with_ethiopic_digit_transaction_does_not_crash(self):
        """End-to-end: a transaction containing a non-ASCII Unicode digit
        must not crash filter_transactions and abort the whole batch."""
        txns = [
            {"txn_id": "clean-1", "sender_id": "a", "receiver_id": "b", "amount": 100},
            {"txn_id": "ethiopic-1", "note": "qty \u1369 widgets", "amount": 50},
        ]
        clean, rejected, details = filter_transactions(txns)
        # Both are clean — no PAN present, no crash.
        assert rejected == 0
        assert len(clean) == 2

    # ------------------------------------------------------------------
    # Non-dict batch element crash
    #
    # txn.get("txn_id", ...) assumes every element is a dict. A bare string
    # element raises AttributeError and previously aborted the whole batch.
    # ------------------------------------------------------------------

    def test_filter_batch_with_bare_string_element_does_not_crash(self):
        """A malformed (non-dict) batch element is rejected individually,
        not allowed to raise and abort the whole batch."""
        txns = [
            {"txn_id": "clean-1", "sender_id": "a", "receiver_id": "b", "amount": 100},
            "4532015112830366",  # bare string — no .get() method
        ]
        clean, rejected, details = filter_transactions(txns)
        assert len(clean) == 1
        assert rejected == 1
        assert details[-1]["reason"] == "Malformed transaction element (not an object) — rejected"

    def test_filter_batch_with_multiple_malformed_elements(self):
        """Several non-dict elements (str, int, list, None) are each
        rejected individually without raising."""
        txns = [
            {"txn_id": "clean-1", "sender_id": "a", "receiver_id": "b", "amount": 100},
            "a bare string",
            12345,
            ["nested", "list"],
            None,
        ]
        clean, rejected, details = filter_transactions(txns)
        assert len(clean) == 1
        assert rejected == 4


# ------------------------------------------------------------------
# Two-pass, evidence-based masking model. Adversarial tests, parametrized across all 3 duplicated
# pan_filter.py copies: the single-pass "any letter breaks the run" model
# could be evaded by inserting one letter into an otherwise-real PAN, and
# separately treated ANY letter/'*' presence as masking even when it was
# just scattered characters with no real masking shape. Each module is
# imported directly here (not just lambdas.detection_agent.pan_filter) so a
# divergence introduced in only one of the 3 copies would be caught.
# ------------------------------------------------------------------

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


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
class TestTwoPassEvidenceBasedMasking:
    """Masking-model regressions, applied identically across all 3 duplicated copies."""

    VALID_PAN_DIGITS = "4532015112830366"

    @pytest.mark.parametrize("variant", [
        "a" + "4532015112830366",            # letter inserted at the start
        "453201511283" + "a" + "0366",        # letter inserted in the middle
        "4532015112830366" + "a",             # letter inserted at the end
        "45320151" + "x" + "1283" + "x" + "0366",  # two letters inserted mid-PAN
    ], ids=["start", "middle", "end", "two_letters"])
    def test_unmasked_pan_with_inserted_letter_is_caught(self, mod, variant):
        """An unmasked real PAN with a letter inserted at various positions
        must still be flagged as a PAN (required adversarial test)."""
        assert mod.contains_full_pan(variant) is True

    @pytest.mark.parametrize("masked_variant", [
        "4532-01**-****-0366",   # existing fixture: 8-char contiguous '*' run
        "4532xxxxxxxx0366",      # existing fixture: 8-char contiguous 'x' run
    ], ids=["star_run", "x_run"])
    def test_genuinely_masked_pan_with_real_contiguous_run_stays_safe(self, mod, masked_variant):
        """A genuinely masked PAN with a real contiguous >=6 mask-char run
        must stay treated as masked/safe (required adversarial test)."""
        assert mod.contains_full_pan(masked_variant) is False

    def test_scattered_isolated_mask_chars_not_forming_a_run_is_flagged(self, mod):
        """A PAN with scattered single mask characters not forming a 6+
        contiguous run must now be treated as real/unmasked (required
        adversarial test)."""
        assert mod.contains_full_pan("4532*0151*1283*0366") is True

    def test_scattered_mask_chars_each_isolated_by_digits_is_flagged(self, mod):
        """Same property, different scatter pattern — no single run of
        mask characters anywhere reaches the 6-character minimum."""
        assert mod.contains_full_pan("45*32*01*51*12*83*03*66") is True

    def test_timestamp_like_field_general_case_is_not_a_false_positive(self, mod):
        """A general-case timestamp must not be a false positive: under
        N1 a calendar-valid ISO-8601 datetime is exempt and
        contributes no digits (matrix row F02).

        NOTE: the literal ``2026-08-19T03:11:39.014082`` (earlier row 9a) is
        also exempt under N1 now; see
        test_pan_filter_spec_compliance.test_iso_timestamp_exempt."""
        assert mod.contains_full_pan("2026-01-01T00:00:00.000001") is False

    def test_cross_field_split_with_interleaved_letter_is_a_known_limitation(self, mod):
        """KNOWN LIMITATION — documented residual (matrix row R1a), not a
        regression: a cross-field fragment with an interior letter or
        interior mask glyph is not reassembled. X2 breaks fragment runs at
        every LETTER and glyph, so ``4532a0151`` contributes ``4532`` and
        ``0151`` and ``1283x0366`` contributes ``1283`` and ``0366``; no
        exact chain concatenation is the PAN. Closing it means bridging
        letters inside fragment runs, which raises schema false positives
        from about 1% to about 7%. See
        test_pan_filter_spec_compliance.test_known_limitation_cross_field_split_with_interleaved_letter_not_caught."""
        txns = [{"txn_id": "split-letter-1", "a": "4532a0151", "b": "1283x0366"}]
        clean, rejected, details = mod.filter_transactions(txns)
        assert rejected == 0
        assert len(clean) == 1

    def test_unrelated_numeric_fields_still_not_falsely_triggered(self, mod):
        """Regression: the exact existing
        test_cross_field_split_not_falsely_triggered_by_unrelated_fields
        fixture, re-run against all 3 copies directly (not just the
        detection_agent copy the base test class above exercises).

        The timestamp field is not part of this fixture (dropped earlier);
        under N1 it is now exempt, see
        test_pan_filter_spec_compliance.test_iso_timestamp_exempt. The
        acc/amount fields produce no false positive (matrix row Z01)."""
        txns = [{
            "txn_id": "clean-1",
            "sender_id": "acc-10293847",
            "receiver_id": "acc-56473829",
            "amount": 289.45,
        }]
        clean, rejected, details = mod.filter_transactions(txns)
        assert rejected == 0
        assert len(clean) == 1

    def test_existing_masked_and_evasion_fixtures_still_hold(self, mod):
        """Spot-check a handful of the existing (pre-two-pass) fixtures
        directly against each module to guard against a copy-specific
        regression in the two-pass rewrite."""
        assert mod.contains_full_pan("4532015112830366") is True
        assert mod.contains_full_pan("4532-0151-1283-0366") is True
        assert mod.contains_full_pan("1043321819600133") is False
        assert mod.contains_full_pan("") is False
        assert mod.contains_full_pan(None) is False
