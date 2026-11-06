"""Domain helpers: registrable domain, punycode, and lookalike detection."""

from __future__ import annotations

# Common two-label public suffixes. A full Public Suffix List would be more
# accurate; this keeps the tool dependency-free (see README, Limitations).
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "co.jp", "com.br",
    "com.sg", "com.my", "co.nz", "co.za", "com.mx",
}

# Characters (and pairs) attackers swap in to imitate a brand.
_CONFUSABLE_PAIRS = {"rn": "m", "vv": "w", "cl": "d"}
_CONFUSABLE_CHARS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "$": "s", "@": "a",
    # Cyrillic and other look-alikes of Latin letters
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "ԁ": "d",
    "ɡ": "g", "һ": "h", "Α": "a", "Ο": "o",
}


def decode_idna(domain: str) -> str:
    """Decode punycode labels (xn--...) to Unicode; leave others untouched."""
    labels = []
    for label in domain.lower().split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.lower().split("."))


def registrable_domain(host: str) -> str:
    """Best-effort 'example.co.uk' / 'example.com' from any host name."""
    labels = [label for label in host.lower().strip(".").split(".") if label]
    if len(labels) < 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _second_level_label(domain: str) -> str:
    reg = registrable_domain(domain)
    return reg.split(".")[0] if reg else ""


def normalize_confusables(label: str) -> str:
    text = label.lower()
    for pair, replacement in _CONFUSABLE_PAIRS.items():
        text = text.replace(pair, replacement)
    return "".join(_CONFUSABLE_CHARS.get(ch, ch) for ch in text)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def is_same_or_subdomain(host: str, protected: str) -> bool:
    host, protected = host.lower().strip("."), protected.lower().strip(".")
    return host == protected or host.endswith("." + protected)


def lookalike(host: str, protected_domains: list[str]) -> tuple[str, str, bool] | None:
    """Return (protected_domain, reason, strong) if host imitates one of them.

    strong=True means a deliberate imitation (homoglyph, edit distance,
    same name on another TLD); strong=False means it only contains the brand.
    """
    decoded = decode_idna(host)
    for protected in protected_domains:
        if is_same_or_subdomain(host, protected) or is_same_or_subdomain(decoded, protected):
            return None

    candidate = _second_level_label(decoded)
    if not candidate:
        return None

    for protected in protected_domains:
        target = _second_level_label(protected)
        if not target:
            continue
        normalized = normalize_confusables(candidate)
        if candidate == target:
            return protected, f"same name as {protected} on a different domain suffix", True
        if normalized == target:
            return protected, f"character substitution imitating {protected} ('{candidate}' reads as '{target}')", True
        if len(target) >= 5:
            distance = levenshtein(candidate, target)
            if distance <= 2:
                return protected, f"{distance} character(s) away from {protected}", True
        if len(target) >= 4 and target in normalized:
            if target not in candidate:
                # The brand only appears after undoing character swaps:
                # deliberate obfuscation, e.g. 'examp1e-login'.
                return protected, f"hides the protected name '{target}' behind character substitution", True
            return protected, f"contains the protected name '{target}'", False
    return None
