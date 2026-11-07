"""Content scanning: secrets, personal data, injected instructions, hidden text.

Rules are plain regular expressions plus the checksums that make a match
believable (Luhn for card and Canadian SIN numbers, mod-97 for IBANs, an
entropy floor for generic "key = value" lines). Standard library only. Every
pattern has bounded repetition and no nested quantifiers, so scanning time
grows in proportion to the text, not worse.

Findings never carry the matched text: a log of what was found must not become
a second copy of it. A finding is (kind, rule, where, n).

This is a net with holes, not a guarantee. It does not decode base64 or other
encodings, does not join a secret split over several values, and a rule list
cannot know a secret format it was never given. See the README's limits.
"""

from __future__ import annotations

import math
import re
import unicodedata

KINDS = ("secrets", "pii", "injection", "hidden")
# which detectors make sense where
ARGUMENT_KINDS = ("secrets", "pii", "hidden")
RESULT_KINDS = ("secrets", "pii", "injection", "hidden")
DESCRIPTION_KINDS = ("injection", "hidden")
ARGUMENT_ACTIONS = ("deny", "flag")
RESULT_ACTIONS = ("redact", "deny", "flag")
DESCRIPTION_ACTIONS = ("hide", "flag")
SECTIONS = {
    "arguments": (ARGUMENT_KINDS, ARGUMENT_ACTIONS),
    "results": (RESULT_KINDS, RESULT_ACTIONS),
    "descriptions": (DESCRIPTION_KINDS, DESCRIPTION_ACTIONS),
    # requests and notifications the SERVER starts (sampling/createMessage,
    # elicitation/create, notifications/message ...): a server's way to put
    # text in front of the client's model without answering any call
    "server_messages": (RESULT_KINDS, RESULT_ACTIONS),
}
MAX_FINDINGS = 20           # reported per message; the rest are counted, not listed

# --------------------------------------------------------------------------
# helpers for the checks that make a match believable
# --------------------------------------------------------------------------


def _entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _luhn(digits: str) -> bool:
    total, flip = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if flip:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        flip = not flip
    return total % 10 == 0


def _digits(text: str) -> str:
    return "".join(ch for ch in text if ch.isdigit())


def _card_ok(text: str) -> bool:
    d = _digits(text)
    if not 13 <= len(d) <= 19 or not _luhn(d):
        return False
    if d[0] == "4":
        return len(d) in (13, 16, 19)
    if d[:2] in ("34", "37"):
        return len(d) == 15
    if d[:2] in ("51", "52", "53", "54", "55") or 2221 <= int(d[:4]) <= 2720:
        return len(d) == 16
    if d[:4] == "6011" or d[:2] == "65" or d[:3] in ("644", "645", "646", "647",
                                                    "648", "649"):
        return len(d) in (16, 19)
    return False


def _sin_ok(text: str) -> bool:
    d = _digits(text)
    return len(d) == 9 and d[0] not in "08" and _luhn(d)


def _iban_ok(text: str) -> bool:
    s = text.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    try:
        number = "".join(str(int(ch, 36)) for ch in moved)
    except ValueError:
        return False
    return int(number) % 97 == 1


def _high_entropy(text: str) -> bool:
    return _entropy(text) >= 3.3


# --------------------------------------------------------------------------
# the rules: (kind, name, compiled pattern, optional check on the matched
# text or on group "v"). A rule with a group named v redacts only that group.
# --------------------------------------------------------------------------

_I = re.IGNORECASE


def _r(kind, name, pattern, check=None, flags=0, needles=None):
    """`needles`: substrings, at least one of which the text must contain
    for the pattern to be worth running (a plain `in` test is far cheaper
    than a regular expression over a megabyte). Matched against the
    lower-cased text when the rule is case-insensitive."""
    if needles is not None and flags & re.IGNORECASE:
        needles = tuple(n.lower() for n in needles)
    return (kind, name, re.compile(pattern, flags), check, needles)


_RULES = [
    # --- secrets: provider token formats --------------------------------
    _r("secrets", "aws_access_key", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b", needles=("AKIA", "ASIA", "AGPA", "AIDA", "AROA")),
    _r("secrets", "github_token",
       r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b", needles=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")),
    _r("secrets", "slack_token", r"\bxox[abposr]-[A-Za-z0-9-]{10,200}", needles=("xox",)),
    _r("secrets", "stripe_key", r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{20,200}\b", needles=("k_live_", "k_test_")),
    _r("secrets", "google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", needles=("AIza",)),
    _r("secrets", "anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{20,300}", needles=("sk-ant-",)),
    _r("secrets", "openai_key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,300}\b",
       _high_entropy, needles=("sk-",)),
    _r("secrets", "npm_token", r"\bnpm_[A-Za-z0-9]{36}\b", needles=("npm_",)),
    _r("secrets", "pypi_token", r"\bpypi-[A-Za-z0-9_-]{50,300}", needles=("pypi-",)),
    _r("secrets", "sendgrid_key", r"\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b", needles=("SG.",)),
    # Formats from public secret-scanner rule lists (for example gitleaks);
    # not checked against each vendor's own documentation.
    _r("secrets", "huggingface_token", r"\bhf_[A-Za-z0-9]{34,200}\b", needles=("hf_",)),
    _r("secrets", "gitlab_token", r"\bglpat-[A-Za-z0-9_-]{20,100}", needles=("glpat-",)),
    _r("secrets", "google_oauth_token", r"\bya29\.[A-Za-z0-9_-]{30,2000}", needles=("ya29.",)),
    _r("secrets", "shopify_token", r"\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b", needles=("shp",)),
    _r("secrets", "digitalocean_token", r"\bdo[por]_v1_[a-f0-9]{64}\b", needles=("_v1_",)),
    _r("secrets", "azure_storage_key", r"\bAccountKey=(?P<v>[A-Za-z0-9+/]{60,200}={0,2})", None, _I,
       needles=("accountkey=",)),
    _r("secrets", "jwt",
       r"\beyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,4000}\.[A-Za-z0-9_-]{8,2000}", needles=("eyJ",)),
    # Tempered body, so a text made of nothing but headers costs time in
    # proportion to its size (the earlier lazy form re-read 16 KB for every
    # header: 100,000 headers took two minutes). A header with no matching END
    # within 16 KB takes what follows it up to that limit: it fails closed.
    _r("secrets", "private_key",
       r"-----BEGIN [A-Z0-9 ]{0,30}PRIVATE KEY(?: BLOCK)?-----"
       r"(?:(?!-----(?:BEGIN|END) )[\s\S]){0,16384}"
       r"(?:-----END [A-Z0-9 ]{0,30}PRIVATE KEY(?: BLOCK)?-----)?", needles=("PRIVATE KEY",)),
    _r("secrets", "db_url_password",
       r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|https?|ftps?|sftp|ssh|smtps?|imaps?)://"
       r"[^\s:/@]{1,100}:(?P<v>[^\s@/]{3,200})@", needles=("://",)),
    _r("secrets", "bearer_token", r"\bBearer\s+(?P<v>[A-Za-z0-9._~+/=-]{24,500})",
       lambda t: _high_entropy(t), _I, needles=("bearer",)),
    _r("secrets", "assigned_secret",
       r"\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|"
       r"client[_-]?secret|passw(?:or)?d|passwd|pwd)[\"']?\s{0,3}[:=]\s{0,3}[\"']?"
       r"(?P<v>[A-Za-z0-9_\-+/=.!@#$%^&*]{12,200})",
       _high_entropy, _I,
       needles=("key", "secret", "token", "passw", "pwd")),
    # --- personal data ---------------------------------------------------
    _r("pii", "card_number", r"(?<![\d.-])(?:\d[ .-]?){12,18}\d(?![\d-])", _card_ok),
    _r("pii", "canadian_sin", r"(?<![\d-])\d{3}[ -]\d{3}[ -]\d{3}(?![\d-])", _sin_ok),
    _r("pii", "us_ssn", r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])"),
    _r("pii", "iban", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b",
       _iban_ok),
    # --- injected instructions (heuristic) ---------------------------------
    _r("injection", "override_instructions",
       r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,30}\b(?:previous|prior|above|"
       r"earlier|preceding|system)\b[^.\n]{0,20}\b(?:instructions?|prompts?|rules?|"
       r"messages?|guidelines?)\b", None, _I,
       needles=("ignore", "disregard", "forget", "override")),
    _r("injection", "hidden_tag", r"</?(?:important|system|instructions?|secret|admin)>",
       None, _I, needles=("<",)),
    _r("injection", "conceal_from_user",
       r"\b(?:do not|don'?t|never)\b[^.\n]{0,30}\b(?:tell|inform|mention|reveal|show|"
       r"notify|alert)\b[^.\n]{0,30}\b(?:the )?(?:user|human)\b", None, _I,
       needles=("not ", "n't", "never")),
    _r("injection", "exfiltrate_credentials",
       r"\b(?:send|post|upload|forward|email|exfiltrate|leak|transmit|include|attach|"
       r"append)\b[^.\n]{0,60}(?:\.ssh\b|id_rsa|\.aws/credentials|\.env\b|/etc/passwd|"
       r"\bapi[_ -]?keys?\b|\bcredentials\b|\bpasswords?\b)", None, _I,
       needles=(".ssh", "id_rsa", ".aws/", ".env", "/etc/passwd", "api", "credential",
                "password")),
    _r("injection", "role_takeover",
       r"(?:^|[\n.]\s{0,3})(?:you are now|new instructions?:|system prompt:|"
       r"from now on,? you)\b", None, _I,
       needles=("you are now", "new instruction", "system prompt", "from now on")),
    # --- hidden text: invisible characters used to smuggle text -----------
    _r("hidden", "invisible_characters",
       "[\u00ad\u200b\u2060-\u2064\u202a-\u202e\u2066-\u2069\ufeff"
       "\U000e0000-\U000e007f]+"),
]

_BY_KIND: dict[str, list] = {k: [r for r in _RULES if r[0] == k] for k in KINDS}


def rule_names(kind: "str | None" = None) -> list[str]:
    return [r[1] for r in _RULES if kind is None or r[0] == kind]


# --------------------------------------------------------------------------
# scanning one string
# --------------------------------------------------------------------------


def _spans(text: str, kinds):
    """(start, end, kind, rule) for every believable match, in order of
    position, overlapping ones merged to the earliest."""
    out = []
    low = None
    for kind in kinds:
        for _k, name, pattern, check, needles in _BY_KIND[kind]:
            if needles is not None:
                hay = text
                if pattern.flags & re.IGNORECASE:
                    low = low if low is not None else text.lower()
                    hay = low
                if not any(n in hay for n in needles):
                    continue
            for m in pattern.finditer(text):
                grp = "v" if "v" in pattern.groupindex else 0
                if check is not None and not check(m.group(grp)):
                    continue
                s, e = m.span(grp)
                if e > s:
                    out.append((s, e, kind, name))
    out.sort()
    return _merge(out)


def _merge(out):
    merged = []
    for item in out:
        if merged and item[0] < merged[-1][1]:
            # overlapping: one span, so no tail of the later match is left
            first = merged[-1]
            merged[-1] = (first[0], max(first[1], item[1]), first[2], first[3])
            continue
        merged.append(item)
    return merged


_INVISIBLE = re.compile(
    "[\u00ad\u200b\u2060-\u2064\u202a-\u202e\u2066-\u2069\ufeff"
    "\U000e0000-\U000e007f]+")


def _view(text: str) -> str:
    """The text as a reader sees it: invisible characters gone and compatible
    forms folded (full-width digits and letters become ASCII). A secret with a
    zero-width space in the middle, or typed in full-width characters, is
    still the secret. ASCII text is its own view."""
    if text.isascii():
        return text
    return _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))


_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_=-])")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Za-z])")
_PCT_RUN = re.compile(r"(?:[A-Za-z0-9._~+_-]|%[0-9A-Fa-f]{2}){6,}")
MAX_DECODE = 1_000_000          # characters of one encoded run worth decoding


def _decoded(view: str):
    """(start, end, label, decoded text) for each base64, hex or
    percent-encoded run in `view` that decodes to UTF-8 text. One level only:
    what is inside a decoded run is not decoded again."""
    import base64
    import binascii
    from urllib.parse import unquote
    out = []
    if "%" in view:
        for m in _PCT_RUN.finditer(view):
            t = m.group(0)
            if "%" in t:
                d = unquote(t, errors="replace") if t.isascii() else t
                if d != t:
                    out.append((m.start(), m.end(), "percent", d))
    for m in _B64_RUN.finditer(view):
        t = m.group(0)
        if len(t) > MAX_DECODE:
            continue
        core = t.rstrip("=")
        try:
            raw = base64.b64decode(core.replace("-", "+").replace("_", "/")
                                   + "=" * (-len(core) % 4), validate=True)
            d = raw.decode("utf-8")
        except (binascii.Error, ValueError):
            continue
        if len(d) >= 8 and sum(ch.isprintable() or ch in "\n\r\t" for ch in d) >= 0.95 * len(d):
            out.append((m.start(), m.end(), "base64", d))
    for m in _HEX_RUN.finditer(view):
        t = m.group(0)
        if len(t) > MAX_DECODE:
            continue
        try:
            d = bytes.fromhex(t).decode("utf-8")
        except ValueError:
            continue
        if len(d) >= 8 and sum(ch.isprintable() or ch in "\n\r\t" for ch in d) >= 0.95 * len(d):
            out.append((m.start(), m.end(), "hex", d))
    return out


def _encoded_spans(view: str, kinds, decode: bool):
    """Spans of encoded runs that hide a believable match. The rule is named
    `base64:github_token` and so on; the whole run is the span."""
    if not decode or not kinds:
        return []
    out = []
    for s, e, label, d in _decoded(view):
        inner = _spans(_view(d), kinds)
        if inner:
            out.append((s, e, inner[0][2], f"{label}:{inner[0][3]}"))
    return out


# Letters of other scripts that read as Latin ones. Folded one-for-one (so
# positions line up) before the injection phrases are matched: a model reads
# "ignore prev\u0456ous instructions" as the phrase. Not applied to secrets,
# which are exact strings. A short table, not the Unicode confusables list.
_CONFUSABLE = str.maketrans({
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u04bb": "h", "\u0501": "d", "\u051b": "q", "\u0410": "A", "\u0412": "B",
    "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H", "\u041e": "O",
    "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u0406": "I",
    # Greek
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03bd": "v", "\u03b9": "i",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H", "\u0399": "I",
    "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P",
    "\u03a4": "T", "\u03a7": "X", "\u03a5": "Y", "\u0396": "Z",
})


def _passes(text: str, kinds, decode: bool = False):
    """(hidden spans on the text itself, other spans on its view, the view)."""
    hidden = _spans(text, ("hidden",)) if "hidden" in kinds else []
    rest = tuple(k for k in kinds if k != "hidden")
    view = _view(text) if rest else text
    spans = _spans(view, rest) if rest else []
    if "injection" in rest and not view.isascii():
        folded = view.translate(_CONFUSABLE)
        if folded != view:
            extra = _spans(folded, ("injection",))
            if extra:
                spans = _merge(sorted(spans + extra))
    if decode and rest:
        enc = _encoded_spans(view, rest, True)
        if enc:
            spans = _merge(sorted(spans + enc))
    return hidden, spans, view


def find(text: str, kinds, decode: bool = False) -> list[tuple[str, str]]:
    """[(kind, rule)] of what `text` contains. No text is returned."""
    if not isinstance(text, str) or len(text) < 8:
        return []
    hidden, rest, _view_text = _passes(text, kinds, decode)
    return [(k, r) for _s, _e, k, r in hidden + rest]


def redact_text(text: str, kinds, decode: bool = False) -> "tuple[str, list[tuple[str, str]]]":
    """`text` with each match replaced by a marker that names the rule
    (hidden characters are removed outright), and what was found. A text
    that held a secret comes back in its view form (see _view): that is the
    form the match was made on."""
    if not isinstance(text, str) or len(text) < 8:
        return text, []
    hidden, rest, view = _passes(text, kinds, decode)
    if not hidden and not rest:
        return text, []
    if hidden:
        text = _INVISIBLE.sub("", text)         # what a reader sees; flag-only
        if not rest:                            # callers do not call us
            return text, [(k, r) for _s, _e, k, r in hidden]
        _h, rest, view = _passes(text, tuple(k for k in kinds if k != "hidden"),
                                 decode)
    if not rest:
        return text, [(k, r) for _s, _e, k, r in hidden]
    parts, last = [], 0
    for s, e, kind, name in rest:
        parts.append(view[last:s])
        parts.append(f"[mcp-leash: redacted {name}]")
        last = e
    parts.append(view[last:])
    return "".join(parts), [(k, r) for _s, _e, k, r in hidden + rest]


# --------------------------------------------------------------------------
# scanning a JSON value
# --------------------------------------------------------------------------

_SKIP_WHEN_BINARY = ("data", "blob")


def _is_binary_field(key, parent: dict) -> bool:
    """The base64 payload of an image / audio / blob resource: large, never
    text, and not worth scanning."""
    return (key in _SKIP_WHEN_BINARY and isinstance(parent.get("mimeType"), str)
            and not parent["mimeType"].startswith("text/")) or key == "blob"


class Report:
    """What a scan found, without any of the matched text."""

    def __init__(self):
        self.items: dict = {}           # (kind, rule, path) -> count

    def add(self, kind: str, rule: str, path: str, n: int = 1) -> None:
        key = (kind, rule, path)
        self.items[key] = self.items.get(key, 0) + n

    def __bool__(self) -> bool:
        return bool(self.items)

    def kinds(self) -> set:
        return {k for k, _r, _p in self.items}

    def listing(self) -> list[dict]:
        out = [{"kind": k, "rule": r, "where": p, "n": n}
               for (k, r, p), n in self.items.items()]
        return out[:MAX_FINDINGS]

    def summary(self) -> str:
        by_rule: dict = {}
        for (k, r, _p), n in self.items.items():
            by_rule[(k, r)] = by_rule.get((k, r), 0) + n
        return ", ".join(f"{n} x {r}" for (_k, r), n in by_rule.items())


def scan_value(value, kinds_for, report: Report, redact: bool = False,
               path: str = "", depth: int = 0, decode: bool = False,
               skip_binary: bool = True):
    """Walk `value` (JSON). `kinds_for` is the tuple of detector kinds to run.
    Returns the value with matches redacted when `redact`, else `value`
    unchanged. Findings go to `report`. Dictionary keys are scanned too (a
    secret can be sent as a key name). `decode` also looks inside base64, hex
    and percent-encoded runs. `skip_binary`: skip the payload of `data`/`blob`
    fields that are declared non-text (an image in an answer: large and not
    worth the time); arguments are scanned in full, since `{"blob": ...}` is
    a field an agent can fill with anything."""
    if depth > 200:
        report.add("secrets", "too_deep_to_scan", path or "$")
        return value
    if isinstance(value, str):
        if redact:
            new, found = redact_text(value, kinds_for, decode)
        else:
            new, found = value, find(value, kinds_for, decode)
        for kind, rule in found:
            report.add(kind, rule, path or "$")
        return new
    if isinstance(value, list):
        out = [scan_value(v, kinds_for, report, redact,
                          f"{path}.{i}" if path else str(i), depth + 1,
                          decode, skip_binary)
               for i, v in enumerate(value)]
        return out if redact else value
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            where = f"{path}.{k}" if path else str(k)
            nk = k
            if isinstance(k, str) and len(k) >= 8:
                knew, kfound = (redact_text(k, kinds_for, decode) if redact
                                else (k, find(k, kinds_for, decode)))
                if kfound:
                    # the key IS the finding: never put it in a path
                    where = f"{path}.<flagged key>" if path else "<flagged key>"
                for kind, rule in kfound:
                    report.add(kind, rule, f"{where} (key)")
                if redact and knew != k:
                    nk = knew
                    n = 1
                    while nk in value or nk in out:     # never merge two keys
                        n += 1
                        nk = f"{knew}#{n}"
            if skip_binary and isinstance(v, str) and _is_binary_field(k, value):
                out[nk] = v
                continue
            out[nk] = scan_value(v, kinds_for, report, redact, where,
                                 depth + 1, decode, skip_binary)
        return out if redact else value
    return value


def scan_params(params, kinds_for, report: Report, decode: bool = False):
    """A call's whole params, not only `arguments`: `_meta` and any other
    member reach the server too, so a secret can ride there. Findings in
    `arguments` keep their short path (`path`, not `arguments.path`)."""
    if not isinstance(params, dict):
        scan_value(params, kinds_for, report, decode=decode, skip_binary=False)
        return
    for k, v in params.items():
        flagged = isinstance(k, str) and len(k) >= 8 and bool(find(k, kinds_for, decode))
        where = "<flagged key>" if flagged else str(k)
        scan_value(v, kinds_for, report, decode=decode, skip_binary=False,
                   path="" if k == "arguments" else where)
        if flagged:
            for kind, rule in find(k, kinds_for, decode):
                report.add(kind, rule, "<flagged key> (key)")


# --------------------------------------------------------------------------
# the policy block
# --------------------------------------------------------------------------


def compile_scan(spec) -> dict:
    """Validate the policy's `scan` block and return it normalised:
    {section: {kind: action}}. Raises ValueError on anything it cannot read
    unambiguously (an unknown section, detector or action). `decode: true`
    (a flag, not a section) makes every scan also look inside base64, hex and
    percent-encoded runs."""
    if spec is None:
        return {}
    if not isinstance(spec, dict):
        raise ValueError("scan must be an object with 'arguments', 'results' "
                         "and/or 'descriptions'")
    out: dict = {}
    for section, body in spec.items():
        if section in ("_comment",):
            continue
        if section == "decode":
            if not isinstance(body, bool):
                raise ValueError("scan.decode must be true or false")
            if body:
                out["decode"] = True
            continue
        if section not in SECTIONS:
            raise ValueError(f"scan: unknown section {section!r} (expected "
                             f"one of {', '.join(SECTIONS)})")
        kinds, actions = SECTIONS[section]
        if not isinstance(body, dict):
            raise ValueError(f"scan.{section} must be an object mapping a "
                             f"detector to an action")
        rules = {}
        for kind, action in body.items():
            if kind not in kinds:
                raise ValueError(f"scan.{section}: {kind!r} is not a detector "
                                 f"there (expected one of {', '.join(kinds)})")
            if action not in actions:
                raise ValueError(f"scan.{section}.{kind}: {action!r} is not an "
                                 f"action there (expected one of "
                                 f"{', '.join(actions)})")
            rules[kind] = action
        if rules:
            out[section] = rules
    return out


def kinds_with(section_rules: dict, action: str) -> tuple:
    return tuple(k for k, a in section_rules.items() if a == action)
