"""
PAN Ingress Filter — PCI-DSS v4.0 compliance boundary.

Three byte-identical copies of this module exist:

  - lambdas/pan_filter/pan_filter.py                  (CANONICAL)
  - lambdas/detection_agent/pan_filter.py             (copy)
  - lambdas/executor_agent/pan_filter/pan_filter.py   (copy)

lambdas/pan_filter/pan_filter.py is canonical: edit the canonical copy, then
copy (``cp lambdas/pan_filter/pan_filter.py <dest>``). Never hand-edit the
copies; tests/test_pan_filter_copies_identical.py compares SHA-256 digests.

Pure standard library (no external dependencies). This filter MUST run
BEFORE any graph processing so no PAN data enters the detection pipeline.
It is the zero-trust ingress boundary: its only job is to BLOCK unmasked
cardholder data at the edge (PCI-DSS v4.0 s3.4).

Scope: payment PAN = 13-19 digits, Luhn-valid, MII 2-6, 81 or 82; UATP, UzCard, Belkart, Troy and Humo are out of scope.

Detection model (rule names used throughout this module):

  character classes           every character is classified once per leaf
      as DIGIT (D1, D5 multi-digit NFKC), FOLD (D4 Default_Ignorable, mask
      glyphs, Lm modifier letters, SEPARATOR_LETTERS, everything else that
      is not a letter) or LETTER.
  N1                          calendar-valid ISO-8601 / RFC 3339 datetime
      substrings whose neighbours are two letters away from any digit are
      exempt (one BREAK token). Linear Step-2 algorithm; never raises.
  W1                          per leaf: some 13-19-digit window of one
      sub-run with at most one bridged letter, a payment MII and a valid
      Luhn checksum. Mask glyphs fold and never suppress anything.
      Float leaves are split at '.' and also tested as one
      exact int||frac candidate.
  X1-X5                       cross-field: exact concatenations of whole
      fragment runs (>= 4 digits, non-float leaves) across consecutive
      digit-bearing leaves, keys included.
  entry validation            filter_transactions accepts only a list;
      every rejection carries its index and the rule that fired.
"""
import calendar
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import unicodedata


def _luhn_valid(number: str) -> bool:
    """Standard Luhn checksum — real card numbers pass this."""
    total = 0
    for i, ch in enumerate(number[::-1]):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# A real PAN is 13-19 digits. These bound every W1 window and every
# X4 exact candidate.
_MIN_PAN_DIGITS = 13
_MAX_PAN_DIGITS = 19

# X2: a run is a cross-field fragment iff it has at least this many
# digits and its leaf is not a float.
_MIN_FRAGMENT_DIGITS = 4

# N1: more than this many valid datetime matches in one leaf -> none
# is exempt (fails toward detection).
_N1_MAX_MATCHES = 64

# The closed mask-glyph set (compared against the first
# character of the NFKC form). FOLD for per-leaf detection; a break in X2.
MASK_GLYPHS = frozenset({"*", "x", "X", "#", "\u2022", "\u25CF", "\u2217"})

# Character-class rule 3b (normative table).
# Lo letters that UTS #39 confusables map to ASCII punctuation
# (dash, dot, bar, exclamation). U+119E is the NFKC image of U+318D,
# included so that NFKC(s) classifies the same as s.
SEPARATOR_LETTERS = frozenset({
    "\u318D",  # ㆍ HANGUL LETTER ARAEA (Korean interpunct use)
    "\u119E",  # HANGUL JUNGSEONG ARAEA (NFKC image of U+318D)
    "\uA78F",  # ꞏ LATIN LETTER SINOLOGICAL DOT
    "\u01C0",  # ǀ LATIN LETTER DENTAL CLICK
    "\u01C1",  # ǁ LATIN LETTER LATERAL CLICK
    "\u01C2",  # ǂ LATIN LETTER ALVEOLAR CLICK
    "\u01C3",  # ǃ LATIN LETTER RETROFLEX CLICK
    "\u1427",  # ᐧ CANADIAN SYLLABICS FINAL MIDDLE DOT
})

# Character-class rule 2 (D4): Default_Ignorable_Code_Point, fixed table copied from
# Unicode 15.1 DerivedCoreProperties.txt. Inclusive (first, last) ranges.
_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)

# One-character class codes, one per ORIGINAL character of a leaf.
_C_DIGIT = "D"    # DIGIT (D1-D3, and D5 multi-digit NFKC)
_C_LETTER = "L"   # LETTER
_C_FOLD = "F"     # FOLD (not a glyph)
_C_GLYPH = "G"    # FOLD, and a mask glyph (breaks X2 fragment runs)
_C_BREAK = "B"    # an N1-exempt datetime character (W1 BREAK / X2 break)


def _is_default_ignorable(cp: int) -> bool:
    for lo, hi in _DEFAULT_IGNORABLE_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def _nfkc(ch: str) -> str:
    try:
        return unicodedata.normalize("NFKC", ch)
    except Exception:  # never raise on odd input (lone surrogates etc.)
        return ch


def _char_digits(ch: str) -> str:
    """ASCII digit string a character contributes: rule 1 (one digit via
    unicodedata.digit) or rule 1a/D5 (every digit of its NFKC form, so the
    result may be longer than one character). '' for a non-digit."""
    v = unicodedata.digit(ch, None)
    if v is not None:
        return str(v)
    n = _nfkc(ch)
    return "".join(
        str(unicodedata.digit(c)) for c in n if unicodedata.digit(c, None) is not None
    )


def _char_class(ch: str) -> str:
    """Classify one ORIGINAL character, rules applied in order."""
    # 1 / 1a: DIGIT (single digit, or D5 multi-digit NFKC form).
    if _char_digits(ch):
        return _C_DIGIT
    # 2: Default_Ignorable_Code_Point (D4) -> FOLD.
    if _is_default_ignorable(ord(ch)):
        return _C_FOLD
    # 3: classify on the first character of the NFKC form.
    n = _nfkc(ch)
    r = n[0] if n else ch
    if r in MASK_GLYPHS:
        return _C_GLYPH
    cat = unicodedata.category(r)
    # 3a: modifier letter -> FOLD.
    if cat == "Lm":
        return _C_FOLD
    # 3b: separator-shaped letter -> FOLD.
    if ch in SEPARATOR_LETTERS or r in SEPARATOR_LETTERS:
        return _C_FOLD
    # 4: LETTER.
    if cat.startswith("L"):
        return _C_LETTER
    # 5: everything else (separators, punctuation, symbols, controls,
    # combining marks, surrogates Cs, ...) -> FOLD.
    return _C_FOLD


class _CharTable(dict):
    """str.translate mapping that computes and caches a per-code-point value
    on first use. Bounded: cleared when it grows past _MAX_ENTRIES, so an
    adversarial stream of distinct code points cannot grow memory without
    limit."""

    _MAX_ENTRIES = 65_536

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    def __missing__(self, cp):
        value = self._fn(chr(cp))
        if len(self) >= self._MAX_ENTRIES:
            self.clear()
        self[cp] = value
        return value


_CLASS_TABLE = _CharTable(_char_class)
_DIGIT_TABLE = _CharTable(_char_digits)


def _leaf_classes(text: str) -> str:
    """One class code per ORIGINAL character of ``text``, computed
    once per leaf and shared by N1, W1 tokenisation and X2."""
    return text.translate(_CLASS_TABLE)


def _digits_of(text: str) -> str:
    """Concatenated ASCII digit string of ``text`` (non-digits contribute
    nothing; D5 characters contribute every digit of their NFKC form)."""
    return text.translate(_DIGIT_TABLE)


# ---------------------------------------------------------------------------
# N1 — ISO-8601 / RFC 3339 datetime exemption
# ---------------------------------------------------------------------------
# N1 datetime pattern (normative).
_N1_RE = re.compile(
    r"(?<![0-9])([0-9]{4})-([0-9]{2})-([0-9]{2})"
    r"(?:[Tt ]([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:[.,]([0-9]{1,9}))?)?"
    r"(?:[ \t]*(?:[Zz]|[+-]([0-9]{2}):?([0-9]{2})))?)?(?![0-9])",
    re.ASCII)

_N1_OFFSET_MINUTES = frozenset({"00", "30", "45"})


def _n1_match_valid(m) -> bool:
    """Step 1 validity (range checks). Any exception means 'not valid'."""
    try:
        year_s, month_s, day_s, hour_s, minute_s, second_s, _frac, off_h, off_m = m.groups()
        year = int(year_s)
        month = int(month_s)
        day = int(day_s)
        if not 1900 <= year <= 2199:
            return False
        if not 1 <= month <= 12:
            return False
        if not 1 <= day <= calendar.monthrange(year, month)[1]:
            return False
        if hour_s is not None and not 0 <= int(hour_s) <= 23:
            return False
        if minute_s is not None and not 0 <= int(minute_s) <= 59:
            return False
        if second_s is not None and not 0 <= int(second_s) <= 60:
            return False
        if off_h is not None:
            if not 0 <= int(off_h) <= 14:
                return False
            if off_m not in _N1_OFFSET_MINUTES:
                return False
        return True
    except Exception:
        return False


def _n1_valid_matches(text: str) -> list:
    """Step 1: the valid ``_N1_RE`` matches of ``text`` in order, as
    (start, end) offsets. An invalid match is discarded without backtracking
    to a shorter match. No cap is applied here."""
    return [(m.start(), m.end()) for m in _N1_RE.finditer(text) if _n1_match_valid(m)]


# Step 2 side-scan outcomes. REACH(n) is the int n (0 or 1).
_SCAN_DIGIT = -1
_SCAN_SAFE = -2
_DL_RE = re.compile("[DL]")


def _scan(cls: str, lo: int, hi: int) -> int:
    """scan() over cls[lo:hi] in the given (forward) order: DIGIT on the
    first DIGIT, SAFE on the second LETTER, otherwise REACH(n)."""
    m = _DL_RE.search(cls, lo, hi)
    if m is None:
        return 0
    if cls[m.start()] == _C_DIGIT:
        return _SCAN_DIGIT
    m = _DL_RE.search(cls, m.start() + 1, hi)
    if m is None:
        return 1
    return _SCAN_DIGIT if cls[m.start()] == _C_DIGIT else _SCAN_SAFE


def _n1_spans_from(text: str, cls: str) -> list:
    """N1 Step 1 + normative linear Step 2 over a precomputed class
    string. Returns the exempt (start, end) spans in order."""
    matches = _n1_valid_matches(text)
    m = len(matches)
    if m == 0 or m > _N1_MAX_MATCHES:
        return []
    n = len(cls)
    rcls = cls[::-1]

    def scan_back(lo: int, hi: int) -> int:
        # scan(reversed(cls[lo:hi])) == forward scan of rcls[n-hi:n-lo].
        return _scan(rcls, n - hi, n - lo)

    dead = [False] * m
    # 1-2. Side scans and local deadness.
    if scan_back(0, matches[0][0]) == _SCAN_DIGIT:
        dead[0] = True
    if _scan(cls, matches[-1][1], n) == _SCAN_DIGIT:
        dead[m - 1] = True
    fwd = [0] * (m - 1)
    bwd = [0] * (m - 1)
    for i in range(m - 1):
        lo, hi = matches[i][1], matches[i + 1][0]
        fwd[i] = _scan(cls, lo, hi)
        bwd[i] = scan_back(lo, hi)
        if fwd[i] == _SCAN_DIGIT:
            dead[i] = True
        if bwd[i] == _SCAN_DIGIT:
            dead[i + 1] = True
    # 3. Propagation through clean gaps.
    # Rightward rule, left-to-right: bwd[i] = REACH(n) and dead[i] =>
    # dead[i+1], unless n == 1 and M[i] ends in Z/z (the Z carry).
    for i in range(m - 1):
        if dead[i] and bwd[i] >= 0:
            if bwd[i] == 1 and text[matches[i][1] - 1] in "Zz":
                continue
            dead[i + 1] = True
    # Leftward rule, right-to-left: fwd[i] = REACH(.) and dead[i+1] => dead[i].
    for i in range(m - 2, -1, -1):
        if dead[i + 1] and fwd[i] >= 0:
            dead[i] = True
    # 4. Matches that are not dead are exempt.
    return [span for span, d in zip(matches, dead) if not d]


def _n1_exempt_spans(text: str) -> list:
    """N1: (start, end) character offsets of the N1-exempt datetime
    matches of ``text``, in order. Parsing never raises: any unexpected
    condition returns [] (no exemption), which errs toward detection."""
    try:
        return _n1_spans_from(text, _leaf_classes(text))
    except Exception:
        return []


def _apply_breaks(cls: str, spans: list) -> str:
    """Replace every exempt span's characters with BREAK codes."""
    if not spans:
        return cls
    parts = []
    pos = 0
    for start, end in spans:
        parts.append(cls[pos:start])
        parts.append(_C_BREAK * (end - start))
        pos = end
    parts.append(cls[pos:])
    return "".join(parts)


def _leaf_break_classes(text: str) -> str:
    """Class string for a leaf with N1-exempt spans already replaced by
    BREAK codes (the same computation feeds W1 and X2)."""
    cls = _leaf_classes(text)
    try:
        spans = _n1_spans_from(text, cls)
    except Exception:
        spans = []
    return _apply_breaks(cls, spans)


# ---------------------------------------------------------------------------
# Sub-runs / W1
# ---------------------------------------------------------------------------
# Maximal same-kind tokens. FOLD and glyph FOLD are one kind for W1.
_W1_TOKEN_RE = re.compile(r"D+|L+|[FG]+|B+")


def _mii_ok(w: str) -> bool:
    """W1(b): payment major-industry identifier gate."""
    return w[0] in "23456" or w[:2] in ("81", "82")


def _w1_digit_string(d: str, bridges: list) -> bool:
    """W1 over one sub-run (d, B): some window d[s:e], 13 <= e-s <= 19, with
    at most one bridge strictly inside (s < b < e), a payment MII and a
    valid Luhn sum. O(1) per window via prefix sums (NFR1)."""
    n = len(d)
    if n < _MIN_PAN_DIGITS:
        return False
    # Prefix sums of plain and doubled Luhn values, split by index parity:
    # plain[p][k] / dbl[p][k] sum positions j < k with j % 2 == p.
    plain = ([0] * (n + 1), [0] * (n + 1))
    dbl = ([0] * (n + 1), [0] * (n + 1))
    for k in range(n):
        v = ord(d[k]) - 48
        dv = v * 2
        if dv > 9:
            dv -= 9
        p = k & 1
        q = p ^ 1
        plain[p][k + 1] = plain[p][k] + v
        plain[q][k + 1] = plain[q][k]
        dbl[p][k + 1] = dbl[p][k] + dv
        dbl[q][k + 1] = dbl[q][k]
    # bc[i] = number of bridge points b with b < i.
    bc = [0] * (n + 1)
    bset = set(bridges)
    for i in range(n):
        bc[i + 1] = bc[i] + (1 if i in bset else 0)
    for s in range(n - _MIN_PAN_DIGITS + 1):
        if not (d[s] in "23456" or d[s:s + 2] in ("81", "82")):
            continue
        for length in range(_MIN_PAN_DIGITS, _MAX_PAN_DIGITS + 1):
            e = s + length
            if e > n:
                break
            # (a) bridges strictly inside: s < b < e.
            if bc[e] - bc[s + 1] > 1:
                continue
            # (c) Luhn: positions with parity (e-1) % 2 take the plain
            # value, the others the doubled value.
            p = (e - 1) & 1
            q = p ^ 1
            total = (plain[p][e] - plain[p][s]) + (dbl[q][e] - dbl[q][s])
            if total % 10 == 0:
                return True
    return False


def _w1_classified(text: str, cls: str) -> bool:
    """W1 over one leaf given its BREAK-applied class string."""
    tokens = [(mt.group()[0], mt.start(), mt.end()) for mt in _W1_TOKEN_RE.finditer(cls)]
    count = len(tokens)

    def outward_is_digit(i: int, step: int) -> bool:
        j = i + step
        if 0 <= j < count and tokens[j][0] in "FG":
            j += step
        return 0 <= j < count and tokens[j][0] == _C_DIGIT

    parts = []
    dlen = 0
    bridges = []
    for i, (kind, start, end) in enumerate(tokens):
        if kind == _C_DIGIT:
            ds = _digits_of(text[start:end])
            parts.append(ds)
            dlen += len(ds)
        elif kind in "FG":
            continue
        elif (kind == _C_LETTER and end - start == 1
              and outward_is_digit(i, -1) and outward_is_digit(i, 1)):
            # Soft bridge: index into d of the first digit after it.
            bridges.append(dlen)
        else:
            # Hard break (LETTER) or BREAK: close the sub-run.
            if dlen >= _MIN_PAN_DIGITS and _w1_digit_string("".join(parts), bridges):
                return True
            parts = []
            dlen = 0
            bridges = []
    return dlen >= _MIN_PAN_DIGITS and _w1_digit_string("".join(parts), bridges)


def _w1_text(text: str) -> bool:
    """W1 + N1 on one str leaf."""
    return _w1_classified(text, _leaf_break_classes(text))


# Float int||frac candidate (normative).
_FLOAT_REPR_RE = re.compile(r"-?([0-9]+)(?:\.([0-9]+))?(?:e[+-]?[0-9]+)?", re.ASCII)


def _float_candidate(s: str) -> str | None:
    """s is str(v) for a Python float v."""
    m = _FLOAT_REPR_RE.fullmatch(s)
    if m is None:            # 'inf', '-inf', 'nan'
        return None
    c = m.group(1) + (m.group(2) or "")
    return c if 13 <= len(c) <= 19 else None


def _w1_float(s: str) -> bool:
    """W1 for a float leaf: str(v).split('.') part by part, plus the exact
    int||frac candidate against MII and Luhn."""
    for part in s.split("."):
        if _w1_text(part):
            return True
    c = _float_candidate(s)
    return c is not None and _mii_ok(c) and _luhn_valid(c)


# ---------------------------------------------------------------------------
# X1-X5 — cross-field reassembly
# ---------------------------------------------------------------------------
class _EmittedLeaf:
    """X1 marker on the walk stack for an already-emitted leaf (dict key)."""

    __slots__ = ("text",)

    def __init__(self, text: str):
        self.text = text


def _iter_leaves(value):
    """X1: yield (text, is_float) for every leaf in traversal order, with an
    explicit stack (no recursion limit). Dict items in insertion order: str
    (key), then the value. List items in order. bool and None emit
    nothing; other scalars emit str(v)."""
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, _EmittedLeaf):
            yield v.text, False
        elif isinstance(v, dict):
            pending = []
            for k, vv in v.items():
                pending.append(_EmittedLeaf(str(k)))
                pending.append(vv)
            stack.extend(reversed(pending))
        elif isinstance(v, list):
            stack.extend(reversed(v))
        elif v is None or isinstance(v, bool):
            continue
        elif isinstance(v, str):
            yield v, False
        elif isinstance(v, float):
            yield str(v), True
        else:
            yield str(v), False


# X2 runs: maximal digit runs where non-glyph FOLD folds; LETTER, glyph and
# BREAK characters break.
_X2_RUN_RE = re.compile(r"[DF]+")


def _x2_runs(text: str, cls: str) -> list:
    """X2: the digit strings of a leaf's runs, in order (BREAK-applied cls)."""
    runs = []
    for mt in _X2_RUN_RE.finditer(cls):
        ds = _digits_of(text[mt.start():mt.end()])
        if ds:
            runs.append(ds)
    return runs


def _x4_chain_flags(chain: list) -> bool:
    """X4/X5: exact concatenations ci..cj, i < j, of 13-19 digits that pass
    the MII gate and Luhn."""
    count = len(chain)
    for i in range(count - 1):
        total = len(chain[i])
        for j in range(i + 1, count):
            total += len(chain[j])
            if total > _MAX_PAN_DIGITS:
                break
            if total >= _MIN_PAN_DIGITS:
                w = "".join(chain[i:j + 1])
                if _mii_ok(w) and _luhn_valid(w):
                    return True
    return False


def _scan_transaction(txn) -> str | None:
    """'W1' if W1 flags any emitted leaf (checked over all leaves
    first), else 'X4' if X4 flags any chain, else None."""
    leaf_runs = []
    for text, is_float in _iter_leaves(txn):
        if is_float:
            if _w1_float(text):
                return "W1"
            runs = _x2_runs(text, _leaf_break_classes(text))
        else:
            cls = _leaf_break_classes(text)
            if _w1_classified(text, cls):
                return "W1"
            runs = _x2_runs(text, cls)
        if runs:
            leaf_runs.append((runs, is_float))

    # X3: run-stream chains.
    chain = []
    for runs, is_float in leaf_runs:
        for idx, run in enumerate(runs):
            if idx > 0:
                if len(chain) >= 2 and _x4_chain_flags(chain):
                    return "X4"
                chain = []
            if not is_float and len(run) >= _MIN_FRAGMENT_DIGITS:
                chain.append(run)
            else:
                if len(chain) >= 2 and _x4_chain_flags(chain):
                    return "X4"
                chain = []
    if len(chain) >= 2 and _x4_chain_flags(chain):
        return "X4"
    return None


def contains_full_pan(text: str) -> bool:
    """
    Detect a full payment PAN in one leaf (W1 plus N1).

    ``None`` and ``""`` return False. Any other non-``str`` input raises
    ``TypeError``. PCI-DSS v4.0 section 3.4 / section 3.5.1.
    """
    if text is None or (isinstance(text, str) and not text):
        return False
    if not isinstance(text, str):
        raise TypeError("text must be a str")
    return _w1_text(text)


_LOCAL_DEV_ONLY_TXN_REF_KEY = b"local-dev-only-txn-ref-key-not-for-production-use"
_resolved_txn_ref_key = None  # lazily resolved — see _txn_ref_key() below

# Explicit opt-in flag for the local-dev-only HMAC key fallback.
# It is reachable ONLY when the operator sets ALLOW_LOCAL_DEV_TXN_REF_KEY=true
# AND the process is not inside a deployed runtime (/var/task), so every
# deployment that does not resolve a Secrets Manager key fails closed.
_ALLOW_LOCAL_DEV_KEY_FLAG = "ALLOW_LOCAL_DEV_TXN_REF_KEY"

# txn_ref key management: the key lives in AWS
# Secrets Manager, never in runtime configuration.
_SECRET_ARN_ENV = "TXN_REF_HMAC_SECRET_ARN"  # nosec B105 -- name of an environment variable, not a secret value
_PLAINTEXT_KEY_ENV = "TXN_REF_HMAC_KEY"
_MIN_KEY_BYTES = 32
_ARN_RE = re.compile(
    r"arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+",
    re.ASCII)
# used only as: _ARN_RE.fullmatch(arn)
_key_lock = threading.Lock()

logger = logging.getLogger(__name__)


def _fetch_secret_string(arn: str):
    """
    Fetch the txn_ref HMAC key from Secrets Manager (the test seam).

    boto3 and botocore are imported lazily so that importing this module
    (and detecting PANs) never needs them. Returns ``SecretString``, which is
    ``None`` when the secret is binary-only.
    """
    import boto3
    from botocore.config import Config

    region = arn.split(":")[3]
    client = boto3.client(
        "secretsmanager",
        region_name=region,
        config=Config(
            connect_timeout=2,
            read_timeout=2,
            retries={"max_attempts": 2, "mode": "standard"},
        ),
    )
    return client.get_secret_value(SecretId=arn).get("SecretString")


def _in_deployed_runtime() -> bool:
    """True inside a Lambda / AgentCore container (the handlers' own signal)."""
    return os.path.isdir("/var/task")


def _txn_ref_key() -> bytes:
    """
    Resolve the HMAC key for txn_ref.

    Order: (1) cached value; (2) a non-empty plaintext TXN_REF_HMAC_KEY in
    the environment is refused; (3) TXN_REF_HMAC_SECRET_ARN, used verbatim,
    must fully match a Secrets Manager ARN, and the fetched secret must be a
    str of at least 32 UTF-8 bytes (the ARN path wins over the dev flag);
    (4) ALLOW_LOCAL_DEV_TXN_REF_KEY=true gives the dev key, but never inside
    a deployed runtime; (5) otherwise raise (fail-closed).

    Failures are never cached and the key value is never logged. Resolved
    lazily, so importing this module never raises.
    """
    global _resolved_txn_ref_key
    if _resolved_txn_ref_key is not None:
        return _resolved_txn_ref_key

    with _key_lock:
        if _resolved_txn_ref_key is not None:
            return _resolved_txn_ref_key

        if os.environ.get(_PLAINTEXT_KEY_ENV):
            logger.error("pan_filter: plaintext %s is not supported", _PLAINTEXT_KEY_ENV)
            raise RuntimeError(
                "TXN_REF_HMAC_KEY in the environment is not supported — the "
                "txn_ref key is read from Secrets Manager (TXN_REF_HMAC_SECRET_ARN)"
            )

        arn = os.environ.get(_SECRET_ARN_ENV)
        if arn:
            if _ARN_RE.fullmatch(arn) is None:
                logger.error("pan_filter: %s is not a valid Secrets Manager ARN", _SECRET_ARN_ENV)
                raise RuntimeError(
                    "TXN_REF_HMAC_SECRET_ARN is not a well-formed Secrets Manager ARN"
                )
            try:
                value = _fetch_secret_string(arn)
            except Exception as exc:
                # WARNING, not ERROR: the RuntimeError below propagates and is
                # logged at ERROR by the caller / Lambda runtime (no log-level
                # MetricFilter exists). Class name only — never the message.
                logger.warning(
                    "pan_filter: txn_ref HMAC key fetch failed (%s)", type(exc).__name__
                )
                raise RuntimeError("txn_ref HMAC key unavailable") from exc
            if not isinstance(value, str) or len(value.encode("utf-8")) < _MIN_KEY_BYTES:
                logger.warning("pan_filter: txn_ref HMAC secret is missing or shorter than 32 bytes")
                raise RuntimeError(
                    "txn_ref HMAC secret must be a string of at least 32 bytes"
                )
            _resolved_txn_ref_key = value.encode("utf-8")
            return _resolved_txn_ref_key

        if os.environ.get(_ALLOW_LOCAL_DEV_KEY_FLAG, "").lower() == "true":
            if _in_deployed_runtime():
                logger.error("pan_filter: local-dev txn_ref key refused in a deployed runtime")
                raise RuntimeError(
                    "ALLOW_LOCAL_DEV_TXN_REF_KEY is not honoured in a deployed runtime"
                )
            logger.warning(
                "pan_filter: %s is not set and ALLOW_LOCAL_DEV_TXN_REF_KEY=true — "
                "using the clearly-marked local-dev-only key. Never use this "
                "in a shared or deployed environment.",
                _SECRET_ARN_ENV,
            )
            _resolved_txn_ref_key = _LOCAL_DEV_ONLY_TXN_REF_KEY
            return _resolved_txn_ref_key

        logger.error("pan_filter: txn_ref HMAC key is not configured")
        raise RuntimeError(
            "TXN_REF_HMAC_SECRET_ARN is not configured — refusing to derive "
            "txn_ref references with a guessable key. Set it to the Secrets "
            "Manager secret ARN, or set ALLOW_LOCAL_DEV_TXN_REF_KEY=true for "
            "local development only."
        )


def _txn_ref(raw_value: str) -> str:
    """
    Non-reversible, keyed reference for a value that may itself carry a PAN
    — an HMAC-SHA256 over a per-deployment secret,
    full 64-hex-char digest, never truncated. Encodes with "surrogatepass"
    so a lone surrogate cannot abort the batch; every string
    without surrogates gives the same bytes as plain UTF-8.
    """
    return hmac.new(
        _txn_ref_key(), raw_value.encode("utf-8", "surrogatepass"), hashlib.sha256
    ).hexdigest()


_REASON_PAN = "Full PAN detected — PCI-DSS v4.0 section 3.4 violation"
_REASON_MALFORMED = "Malformed transaction element (not an object) — rejected"


def filter_transactions(txns: list) -> tuple:
    """
    Filter a batch of transactions, rejecting any that contain PAN data
    (per-leaf W1, then X1-X5 cross-field; then entry validation).

    Raises TypeError unless ``type(txns) is list`` (checked first, before any
    HMAC work). Each rejection detail is
    ``{"index", "txn_ref", "reason", "rule"}`` where ``rule`` is "W1", "X4"
    or "MALFORMED". This is internal output: the handlers decide what
    reaches an invoker.

    Returns:
        tuple: (clean_transactions, rejected_count, rejection_details)
    """
    if type(txns) is not list:
        raise TypeError("transactions must be a list")
    if not txns:
        return [], 0, []
    # Resolve the key once per call, so a misconfigured deployment fails
    # every batch the same way.
    _txn_ref_key()

    clean = []
    rejected_count = 0
    rejection_details = []

    for index, txn in enumerate(txns):
        # A non-dict element is rejected individually rather than aborting
        # the batch. ASCII-only serialisation cannot fail to
        # encode; default=str covers exotic types.
        if not isinstance(txn, dict):
            rejected_count += 1
            rejection_details.append({
                "index": index,
                "txn_ref": _txn_ref(json.dumps(txn, ensure_ascii=True, default=str, sort_keys=False)),
                "reason": _REASON_MALFORMED,
                "rule": "MALFORMED",
            })
            continue

        rule = _scan_transaction(txn)
        if rule is not None:
            rejected_count += 1
            rejection_details.append({
                "index": index,
                # Keyed reference instead of the raw identifier:
                # txn_id itself may carry a PAN.
                "txn_ref": _txn_ref(str(txn.get("txn_id", "UNKNOWN"))),
                "reason": _REASON_PAN,
                "rule": rule,
            })
        else:
            clean.append(txn)

    return clean, rejected_count, rejection_details
