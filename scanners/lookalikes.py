"""Generate typosquat / lookalike domain candidates (no network I/O)."""

from __future__ import annotations

import re
from typing import Iterable

# QWERTY adjacent keys for typo generation
ADJACENT = {
    "a": "qwsz",
    "b": "vghn",
    "c": "xdfv",
    "d": "erfcxs",
    "e": "rdsw",
    "f": "rtgvcd",
    "g": "tyhbvf",
    "h": "yujnbg",
    "i": "uojk",
    "j": "uikmnh",
    "k": "iolmj",
    "l": "opk",
    "m": "njk",
    "n": "bhjm",
    "o": "iplk",
    "p": "ol",
    "q": "wa",
    "r": "edft",
    "s": "awedxz",
    "t": "rfgy",
    "u": "yhji",
    "v": "cfgb",
    "w": "qeas",
    "x": "zsdc",
    "y": "tghu",
    "z": "asx",
    "0": "9-",
    "1": "2q",
    "2": "13w",
    "3": "24e",
    "4": "35r",
    "5": "46t",
    "6": "57y",
    "7": "68u",
    "8": "79i",
    "9": "80o",
}

# ASCII / Latin lookalike substitutions (domain-label safe)
HOMOGLYPH_ASCII: dict[str, list[str]] = {
    "a": ["4"],
    "b": ["8"],
    "e": ["3"],
    "g": ["9", "q"],
    "i": ["1", "l"],
    "l": ["1", "i"],
    "o": ["0"],
    "s": ["5"],
    "t": ["7"],
    "z": ["2"],
    "0": ["o"],
    "1": ["l", "i"],
    "m": ["rn", "nn"],
    "w": ["vv", "uu"],
    "d": ["cl"],
    "n": ["m"],  # common OCR/confusion; keep sparse
}

# Common Unicode Latin/Cyrillic lookalikes → encoded to punycode (xn--)
HOMOGLYPH_UNICODE: dict[str, list[str]] = {
    "a": ["а", "ɑ"],  # Cyrillic а, Latin alpha
    "c": ["с", "ϲ"],
    "e": ["е", "ė"],
    "i": ["і", "ɩ"],
    "j": ["ј"],
    "o": ["о", "ο"],
    "p": ["р"],
    "s": ["ѕ"],
    "x": ["х"],
    "y": ["у", "ү"],
    "h": ["һ"],
    "b": ["Ь"],
}

ALT_TLDS = (
    ".com",
    ".net",
    ".org",
    ".co",
    ".io",
    ".ai",
    ".sg",
    ".com.sg",
    ".info",
    ".biz",
)

# Longest-first so com.sg wins over .sg
_MULTI_TLDS = tuple(sorted(
    (t for t in ALT_TLDS if t.count(".") > 1),
    key=len,
    reverse=True,
))

COMMON_PREFIXES = (
    "login-",
    "secure-",
    "support-",
    "my-",
    "account-",
    "verify-",
    "signin-",
    "auth-",
    "portal-",
    "help-",
)
COMMON_SUFFIXES = (
    "-login",
    "-secure",
    "-support",
    "-account",
    "-verify",
    "-portal",
    "-help",
    "-auth",
)


def split_domain(domain: str) -> tuple[str, str]:
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0].split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    for multi in _MULTI_TLDS:
        if domain.endswith(multi) and len(domain) > len(multi):
            return domain[: -len(multi)], multi
    parts = domain.rsplit(".", 1)
    if len(parts) == 2 and parts[1]:
        return parts[0], "." + parts[1]
    return domain, ".com"


def missing_char(label: str) -> set[str]:
    out: set[str] = set()
    if len(label) < 3:
        return out
    for i in range(len(label)):
        candidate = label[:i] + label[i + 1 :]
        if candidate and candidate != label:
            out.add(candidate)
    return out


def adjacent_key(label: str) -> set[str]:
    out: set[str] = set()
    for i, ch in enumerate(label):
        for nb in ADJACENT.get(ch, ""):
            out.add(label[:i] + nb + label[i + 1 :])
    return out


def hyphenation(label: str) -> set[str]:
    """Insert hyphens and/or remove existing hyphens."""
    out: set[str] = set()
    if "-" in label:
        out.add(label.replace("-", ""))
        # also drop one hyphen at a time
        parts = label.split("-")
        if len(parts) > 2:
            for i in range(len(parts) - 1):
                merged = "-".join(parts[:i] + [parts[i] + parts[i + 1]] + parts[i + 2 :])
                out.add(merged)
    # insert hyphen between positions
    bare = label.replace("-", "")
    for i in range(2, len(bare) - 1):
        out.add(bare[:i] + "-" + bare[i:])
    return {c for c in out if c and c != label}


def double_char(label: str) -> set[str]:
    out: set[str] = set()
    for i, ch in enumerate(label):
        out.add(label[:i] + ch + label[i:])
    return out


def swap_adjacent(label: str) -> set[str]:
    out: set[str] = set()
    chars = list(label)
    for i in range(len(chars) - 1):
        swapped = chars[:]
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        out.add("".join(swapped))
    return out


def plural_singular(label: str) -> set[str]:
    out: set[str] = set()
    bare = label.replace("-", "")
    if bare.endswith("s") and len(bare) > 3:
        out.add(label[:-1] if label.endswith("s") else bare[:-1])
    else:
        out.add(label + "s")
    if bare.endswith("ies") and len(bare) > 4:
        out.add(bare[:-3] + "y")
    elif bare.endswith("y") and len(bare) > 2:
        out.add(bare[:-1] + "ies")
    return {c for c in out if c and c != label}


def homoglyphs_ascii(label: str) -> set[str]:
    """One-position ASCII lookalike substitutions (incl. multi-char like rn→m)."""
    out: set[str] = set()
    for i, ch in enumerate(label):
        for rep in HOMOGLYPH_ASCII.get(ch, []):
            out.add(label[:i] + rep + label[i + 1 :])
    # reverse multi-char: rn / vv inside label
    for multi, single in (("rn", "m"), ("nn", "m"), ("vv", "w"), ("uu", "w"), ("cl", "d")):
        idx = 0
        while True:
            j = label.find(multi, idx)
            if j < 0:
                break
            out.add(label[:j] + single + label[j + len(multi) :])
            idx = j + 1
    return {c for c in out if c and c != label}


def homoglyphs_punycode(label: str) -> set[str]:
    """Unicode lookalikes encoded as IDNA/punycode labels."""
    out: set[str] = set()
    for i, ch in enumerate(label):
        for rep in HOMOGLYPH_UNICODE.get(ch, []):
            mixed = label[:i] + rep + label[i + 1 :]
            try:
                # Encode Unicode label to punycode (xn--...)
                encoded = mixed.encode("idna").decode("ascii")
                if encoded and encoded != label:
                    out.add(encoded)
            except (UnicodeError, UnicodeDecodeError):
                continue
    return out


def bit_flips(label: str) -> set[str]:
    """Single-bit flips that stay in [a-z0-9-]."""
    out: set[str] = set()
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    for i, ch in enumerate(label):
        code = ord(ch)
        for bit in range(8):
            flipped = code ^ (1 << bit)
            if flipped == code:
                continue
            try:
                new_ch = chr(flipped)
            except ValueError:
                continue
            if new_ch not in allowed:
                continue
            # labels cannot start/end with hyphen
            candidate = label[:i] + new_ch + label[i + 1 :]
            if candidate.startswith("-") or candidate.endswith("-") or "--" in candidate:
                continue
            if candidate != label:
                out.add(candidate)
    return out


def brand_affixes(brand: str, tld: str) -> set[str]:
    brand = re.sub(r"[^a-z0-9-]", "", brand.lower())
    if not brand:
        return set()
    out = {f"{p}{brand}{tld}" for p in COMMON_PREFIXES}
    out |= {f"{brand}{s}{tld}" for s in COMMON_SUFFIXES}
    return out


def _to_puny_host(host: str) -> str | None:
    """Normalize a host that may contain Unicode labels to ASCII/IDNA."""
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return None


def generate_lookalikes(domain: str, brand: str = "", limit: int = 80) -> list[dict]:
    """Return candidate lookalike domains with generation reason."""
    label, tld = split_domain(domain)
    brand_clean = re.sub(r"[^a-z0-9-]", "", (brand or label).lower())
    candidates: dict[str, str] = {}

    def add(hosts: Iterable[str], reason: str) -> None:
        for h in hosts:
            h = h.strip(".").lower()
            if not h:
                continue
            # Allow Unicode through IDNA
            if not re.match(r"^[a-z0-9.-]+$", h):
                encoded = _to_puny_host(h)
                if not encoded:
                    continue
                h = encoded
            if h == f"{label}{tld}" or "." not in h:
                continue
            # skip pathological length (full FQDN up to 253; label parts 63)
            if len(h) > 253:
                continue
            if any(len(p) > 63 for p in h.split(".")):
                continue
            if not re.match(r"^[a-z0-9.-]+$", h):
                continue
            candidates.setdefault(h, reason)

    # same label, alt TLDs (incl. .com.sg, .ai, .io, …)
    for alt in ALT_TLDS:
        if alt != tld:
            add([f"{label}{alt}"], f"TLD variant ({tld} → {alt})")

    # classic typos
    for c in missing_char(label):
        add([f"{c}{tld}"], "Missing character typosquat")
    for c in adjacent_key(label):
        add([f"{c}{tld}"], "Adjacent-key typosquat")
    for c in hyphenation(label):
        add([f"{c}{tld}"], "Hyphen insertion/removal")
    for c in double_char(label):
        add([f"{c}{tld}"], "Doubled character typosquat")
    for c in swap_adjacent(label):
        add([f"{c}{tld}"], "Transposed characters")

    # plural / singular
    for c in plural_singular(label):
        add([f"{c}{tld}"], "Plural/singular variant")

    # homoglyphs
    for c in homoglyphs_ascii(label):
        add([f"{c}{tld}"], "Homoglyph (ASCII lookalike)")
    for c in homoglyphs_punycode(label):
        add([f"{c}{tld}"], "Homoglyph (IDN/punycode)")

    # bit-flips (can be many — still deduped / limited)
    for c in bit_flips(label):
        add([f"{c}{tld}"], "Bit-flip variant")

    # brand prefixes / suffixes + brand as apex
    if brand_clean:
        add(brand_affixes(brand_clean, tld), "Brand prefix/suffix phishing-style hostname")
        # also try affixes on a few popular TLDs
        for alt in (".com", ".net", ".org", ".sg", ".co", ".io", ".ai"):
            if alt != tld:
                add(
                    [f"{p}{brand_clean}{alt}" for p in ("login-", "secure-", "support-")],
                    f"Brand prefix + TLD ({alt})",
                )
        if brand_clean != label:
            add([f"{brand_clean}{tld}"], "Brand as apex label")
            for alt in ALT_TLDS:
                add([f"{brand_clean}{alt}"], f"Brand + TLD ({alt})")

    items = [{"domain": d, "reason": r} for d, r in candidates.items()]
    # Prefer shorter / more similar first (simple heuristic)
    primary = f"{label}{tld}"
    items.sort(key=lambda x: (abs(len(x["domain"]) - len(primary)), x["domain"]))
    return items[:limit]
