"""Shape and entropy detectors for secrets and personal data in captured text.

Recording: every detector is off by default. Turn detectors on per recorder with
``redaction_policy={"detectors": ["aws_access_key_id", "jwt"]}`` (or ``["all"]``); matches are
replaced with ``[REDACTED]`` before anything is hashed or written. With no detectors enabled,
redaction output is byte-identical to SAGE 2.2.

Scanning: ``sage scan`` runs every detector, plus the ``sensitive_key`` check, over a finished
pack, bundle, or journal. Findings carry a location and rule id, never the matched text.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

DETECTOR_PREFIX = "detector:"

Finder = Callable[[str, str], Iterator[tuple[int, int]]]


@dataclass(frozen=True)
class Detector:
    rule_id: str
    description: str
    find: Finder


def _regex_finder(pattern: str, flags: int = 0, check: Callable[[str], bool] | None = None) -> Finder:
    regex = re.compile(pattern, flags)

    def find(text: str, key: str = "") -> Iterator[tuple[int, int]]:
        for match in regex.finditer(text):
            if check is None or check(match.group(0)):
                yield match.span()

    return find


# --- payment cards -------------------------------------------------------------------------------

_CARD_RE = re.compile(r"(?<![\w.\-])\d(?:[ \-]?\d){12,18}(?![\w.\-])")
# Issuer prefixes (IIN ranges) and lengths for Visa, Mastercard, Amex, Discover, JCB, Diners.
_CARD_BRANDS = (
    (re.compile(r"4"), (13, 16, 19)),
    (re.compile(r"5[1-5]|2(?:2[2-9]|[3-6]\d|7[01]|720)"), (16,)),
    (re.compile(r"3[47]"), (15,)),
    (re.compile(r"6(?:011|5|4[4-9])"), (16, 19)),
    (re.compile(r"35(?:2[89]|[3-8]\d)"), (16, 19)),
    (re.compile(r"3(?:0[0-5]|[689])"), (14,)),
)


def luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def is_card_number(candidate: str) -> bool:
    digits = re.sub(r"[ \-]", "", candidate)
    if not digits.isdigit():
        return False
    # Mixed separators ("4111-1111 1111") are not how card numbers are written.
    if " " in candidate and "-" in candidate:
        return False
    for prefix, lengths in _CARD_BRANDS:
        if len(digits) in lengths and prefix.match(digits):
            return luhn_valid(digits)
    return False


def _find_cards(text: str, key: str = "") -> Iterator[tuple[int, int]]:
    for match in _CARD_RE.finditer(text):
        if is_card_number(match.group(0)):
            yield match.span()


# --- high entropy --------------------------------------------------------------------------------

_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+_\-]{24,}={0,2}")
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
# Padded base64 lengths of 16, 20, 32, 48 and 64 byte digests and ids.
_DIGEST_B64_LENGTHS = {24, 28, 44, 64, 88}
_DIGEST_KEY_RE = re.compile(
    r"(?:^|[._\-])(?:id|ids|hash|digest|sha\d*|checksum|etag|fingerprint|mac|sig|signature|nonce|merkle\w*"
    r"|public_key|publickey|pubkey)$"
    r"|_id$|_hash$|_digest$"
)
ENTROPY_MIN_LENGTH = 24
ENTROPY_MIN_BITS = 4.0


def shannon_bits(text: str) -> float:
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _looks_like_secret_token(token: str) -> bool:
    core = token.rstrip("=")
    if len(core) < ENTROPY_MIN_LENGTH:
        return False
    if _HEX_RE.fullmatch(core) or _UUID_RE.fullmatch(core):
        return False
    if token.endswith("=") and len(token) in _DIGEST_B64_LENGTHS:
        return False
    segments = [s for s in re.split(r"[-_]", core) if s]
    if len(segments) > 1 and sum(s.isalpha() and len(s) >= 3 for s in segments) * 2 >= len(segments):
        return False  # kebab or snake identifier made of words ("Order-History-For-Acme-2026")
    upper = sum(c.isupper() for c in core)
    lower = sum(c.islower() for c in core)
    digit = sum(c.isdigit() for c in core)
    if upper < 2 or lower < 2 or digit < 2:
        return False
    return shannon_bits(core) >= ENTROPY_MIN_BITS


def _find_high_entropy(text: str, key: str = "") -> Iterator[tuple[int, int]]:
    if key and _DIGEST_KEY_RE.search(key.lower()):
        return
    for match in _ENTROPY_TOKEN_RE.finditer(text):
        if _looks_like_secret_token(match.group(0)):
            yield match.span()


# --- email ---------------------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"(?<![\w.+\-])[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.([A-Za-z]{2,24})\b")
# "logo@2x.png" and "pkg@scope.js" are file names, not addresses.
_FILE_EXTENSIONS = frozenset(
    "png jpg jpeg gif svg webp bmp ico js mjs ts tsx jsx py json css html md txt yaml yml toml lock".split()
)


def _find_emails(text: str, key: str = "") -> Iterator[tuple[int, int]]:
    for match in _EMAIL_RE.finditer(text):
        if match.group(1).lower() not in _FILE_EXTENSIONS:
            yield match.span()


# --- catalog -------------------------------------------------------------------------------------

DETECTORS: dict[str, Detector] = {
    d.rule_id: d
    for d in (
        Detector(
            "openai_key",
            "OpenAI API keys (sk-, sk-proj-, sk-svcacct-, sk-admin-)",
            _regex_finder(r"(?<![\w-])sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
        ),
        Detector(
            "anthropic_key",
            "Anthropic API keys (sk-ant-)",
            _regex_finder(r"(?<![\w-])sk-ant-[A-Za-z0-9_\-]{20,}"),
        ),
        Detector(
            "aws_access_key_id",
            "AWS access key ids (AKIA long-term, ASIA temporary)",
            _regex_finder(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
        ),
        Detector(
            "github_token",
            "GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)",
            _regex_finder(r"(?<![\w])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
        ),
        Detector(
            "slack_token",
            "Slack tokens (xoxa-, xoxb-, xoxp-, xoxo-, xoxs-, xoxr-)",
            _regex_finder(r"(?<![\w])xox[abposr]-[A-Za-z0-9\-]{10,}"),
        ),
        Detector(
            "google_api_key",
            "Google API keys (AIza)",
            _regex_finder(r"(?<![\w])AIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"),
        ),
        Detector(
            "stripe_key",
            "Stripe secret and restricted keys (sk_live_, rk_live_, sk_test_, rk_test_)",
            _regex_finder(r"(?<![\w])[sr]k_(?:live|test)_[0-9A-Za-z]{16,}"),
        ),
        Detector(
            "private_key_pem",
            "PEM private key blocks (BEGIN ... PRIVATE KEY)",
            _regex_finder(
                r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
                r"(?:[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)?"
            ),
        ),
        Detector(
            "jwt",
            "JSON Web Tokens (three base64url parts, header and payload start with eyJ)",
            _regex_finder(r"(?<![\w-])eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        ),
        Detector(
            "bearer_token",
            "HTTP Bearer credentials",
            _regex_finder(r"\bBearer\s+[A-Za-z0-9_\-\.=+/]{8,}"),
        ),
        Detector("email", "Email addresses", _find_emails),
        Detector("card_number", "Payment card numbers (issuer prefix, length and Luhn check)", _find_cards),
        Detector(
            "high_entropy",
            "Long random-looking tokens (24+ chars, mixed case and digits, high Shannon entropy)",
            _find_high_entropy,
        ),
        Detector(
            "local_path",
            "Absolute local paths that name a user or machine (C:\\..., /home/..., /Users/..., /root/...)",
            _regex_finder(
                r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]+[^\s\"'<>|]+"
                r"|(?<![\w.~\-/])/(?:home|Users|root)/[^\s\"'<>|]+"
            ),
        ),
    )
}

ALL_DETECTORS = tuple(DETECTORS)


def resolve_detector_ids(names: Iterable[str] | str | None) -> tuple[str, ...]:
    """Validate and order detector ids. ``"all"`` enables every detector."""
    if not names:
        return ()
    if isinstance(names, str):
        names = [names]
    wanted: list[str] = []
    for name in names:
        name = str(name).strip()
        if name == "all":
            return ALL_DETECTORS
        if name not in DETECTORS:
            raise ValueError(f"unknown redaction detector {name!r}; known: {', '.join(ALL_DETECTORS)}")
        if name not in wanted:
            wanted.append(name)
    return tuple(d for d in ALL_DETECTORS if d in wanted)


def find_spans(text: str, rule_ids: Iterable[str], *, key: str = "") -> list[tuple[int, int, str]]:
    """Non-overlapping ``(start, end, rule_id)`` matches, earliest and longest first."""
    hits: list[tuple[int, int, str]] = []
    for rule_id in rule_ids:
        for start, end in DETECTORS[rule_id].find(text, key):
            if end > start:
                hits.append((start, end, rule_id))
    hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
    merged: list[tuple[int, int, str]] = []
    for hit in hits:
        if merged and hit[0] < merged[-1][1]:
            continue
        merged.append(hit)
    return merged


def apply_detectors(text: str, rule_ids: tuple[str, ...], *, key: str = "") -> tuple[str, list[str]]:
    """Replace every detector match with ``[REDACTED]``; return the text and the rule ids that fired."""
    hits = find_spans(text, rule_ids, key=key)
    if not hits:
        return text, []
    out: list[str] = []
    cursor = 0
    for start, end, _rule in hits:
        out.append(text[cursor:start])
        out.append("[REDACTED]")
        cursor = end
    out.append(text[cursor:])
    fired = sorted({rule for _s, _e, rule in hits})
    return "".join(out), fired


def split_detector_patterns(patterns: Iterable[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split a value-pattern tuple into plain regexes and ``detector:<id>`` entries."""
    regexes: list[str] = []
    detectors: list[str] = []
    for pattern in patterns:
        if pattern.startswith(DETECTOR_PREFIX):
            detectors.append(pattern[len(DETECTOR_PREFIX):])
        else:
            regexes.append(pattern)
    return tuple(regexes), tuple(detectors)
