"""
Heuristic phishing-URL detector.

Previously, app/phishing_prediction/views.py was a byte-for-byte copy of
app/sqlprediction/views.py: it vectorized the URL against a list of SQL
keywords ("SELECT", "UNION", "--", ...) and ran it through a pickled model
(dumped_models/phishing/rf.joblib). That model expects the same 112-length
SQL-signature vector as the SQL-injection model, so nothing about that path
actually looked at phishing indicators — it was unwired dead code that
happened to share a name.

This module replaces it with real, well-known phishing-URL heuristics
(no ML model, no network calls, so it stays fast and deterministic for
tests): IP-literal hosts, punycode/homograph hostnames, "@" redirection
tricks, URL shorteners, brand-name lookalikes/typosquatting, suspicious
keyword+hyphen combinations, excessive subdomains, etc. Each check
contributes a weight to a 0-1 score; reasons are returned alongside the
verdict so callers (and tests) can see *why* a URL was flagged.
"""

import re
from urllib.parse import urlparse

# Well-known brands commonly impersonated in phishing URLs. Not exhaustive —
# meant to catch the most common lookalike/typosquat patterns.
KNOWN_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "bankofamerica", "wellsfargo", "chase",
    "linkedin", "whatsapp", "outlook", "office365", "dropbox", "adobe",
    "coinbase", "binance", "irs", "usps", "dhl", "fedex",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly", "bl.ink", "tiny.cc",
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "secure", "signin", "sign-in",
    "confirm", "password", "banking", "webscr", "suspend", "unlock",
    "recover", "billing", "invoice", "wallet",
]

LONG_URL_THRESHOLD = 75
MANY_HYPHENS_THRESHOLD = 3
MANY_SUBDOMAINS_THRESHOLD = 4
LOOKALIKE_MAX_DISTANCE = 2

# Weight contributed to the score by each matched heuristic. brand_lookalike
# is deliberately high enough to flag a URL on its own (a lone typosquat
# like "paypa1.com" with nothing else suspicious is still phishing).
WEIGHTS = {
    "ip_host": 0.35,
    "punycode_host": 0.30,
    "at_symbol": 0.20,
    "shortener": 0.20,
    "brand_lookalike": 0.50,
    "many_subdomains": 0.10,
    "suspicious_keyword": 0.10,
    "keyword_with_hyphen": 0.15,
    "no_https": 0.05,
    "long_url": 0.05,
    "many_hyphens": 0.10,
    "non_standard_port": 0.10,
    "redirect_in_path": 0.10,
}

PHISHING_THRESHOLD = 0.5

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _levenshtein(a, b):
    """Plain-Python edit distance (no third-party dependency needed)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i] + [0] * len(b)
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current_row[j] = min(
                previous_row[j] + 1,      # deletion
                current_row[j - 1] + 1,   # insertion
                previous_row[j - 1] + cost,  # substitution
            )
        previous_row = current_row
    return previous_row[-1]


def _registrable_domain(hostname):
    """
    Best-effort "second-level domain" extraction without a public-suffix
    list (e.g. "login.accounts.paypal-secure.com" -> "paypal-secure").
    Good enough for heuristic scoring; not meant to be a real PSL parser.
    """
    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname
    return labels[-2]


def _brand_lookalike(hostname):
    """
    Returns the impersonated brand name if the hostname looks like a
    typosquat or a brand-in-subdomain trick, else None.
    """
    registrable = _registrable_domain(hostname)

    for brand in KNOWN_BRANDS:
        if registrable == brand:
            continue  # this genuinely is the brand's own domain

        # Case 1: near-miss spelling of the brand itself (paypa1, gogle, ...)
        if 0 < _levenshtein(registrable, brand) <= LOOKALIKE_MAX_DISTANCE:
            return brand

        # Case 2: brand name embedded in a longer label/subdomain that
        # isn't the registrable domain itself, e.g.
        # "paypal.com.verify-user.ru" or "secure-paypal-login.net"
        if brand in hostname and brand != registrable:
            return brand

    return None


def extract_features(url):
    """
    Runs every heuristic against `url` and returns (score, reasons) where
    score is clamped to [0, 1] and reasons is a list of human-readable
    strings describing every heuristic that fired.
    """
    reasons = []
    score = 0.0

    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = (parsed.hostname or "").lower()
    netloc = parsed.netloc or ""

    def flag(key, message):
        nonlocal score
        score += WEIGHTS[key]
        reasons.append(message)

    if not hostname:
        return 0.0, ["Could not parse a hostname from the URL."]

    if _IPV4_RE.match(hostname):
        flag("ip_host", "Hostname is a raw IP address instead of a domain name.")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        flag("punycode_host", "Hostname uses punycode, often used to spoof look-alike characters.")

    if "@" in netloc:
        flag("at_symbol", "URL contains '@', which browsers use to discard everything before it as a fake 'username'.")

    if hostname in URL_SHORTENERS:
        flag("shortener", f"'{hostname}' is a URL-shortening service that hides the real destination.")

    brand = _brand_lookalike(hostname)
    if brand:
        flag("brand_lookalike", f"Hostname '{hostname}' looks like it is impersonating '{brand}'.")

    if hostname.count(".") >= MANY_SUBDOMAINS_THRESHOLD:
        flag("many_subdomains", f"Hostname has an unusually large number of subdomains ({hostname.count('.') + 1} labels).")

    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    has_keyword = any(keyword in path_and_query or keyword in hostname for keyword in SUSPICIOUS_KEYWORDS)
    if has_keyword:
        flag("suspicious_keyword", "URL contains a sensitive keyword (login/verify/account/...).")
        if "-" in hostname:
            flag("keyword_with_hyphen", "That keyword is combined with a hyphenated domain, a common phishing pattern.")

    if parsed.scheme != "https":
        flag("no_https", "URL does not use HTTPS.")

    if len(url) > LONG_URL_THRESHOLD:
        flag("long_url", f"URL is unusually long ({len(url)} characters).")

    if hostname.count("-") >= MANY_HYPHENS_THRESHOLD:
        flag("many_hyphens", f"Domain has an unusually large number of hyphens ({hostname.count('-')}).")

    if parsed.port is not None and parsed.port not in (80, 443):
        flag("non_standard_port", f"URL uses a non-standard port ({parsed.port}).")

    if "//" in (parsed.path or ""):
        flag("redirect_in_path", "Path contains an embedded '//', a common open-redirect trick.")

    return min(score, 1.0), reasons


def analyze_url(url):
    """
    Public entry point. Returns a dict:
        {
            "is_phishing": bool,
            "score": float,       # 0.0 - 1.0
            "reasons": [str, ...],
        }
    """
    score, reasons = extract_features(url)
    score = round(score, 3)  # avoid float-accumulation edge cases at the threshold
    return {
        "is_phishing": score >= PHISHING_THRESHOLD,
        "score": score,
        "reasons": reasons,
    }
