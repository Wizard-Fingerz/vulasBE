"""
Computes the 111-feature vector the resurrected RandomForestClassifier
(app/dumped_models/phishing/rf.joblib) was trained on — the feature set
from Vrbancic, Fister & Podgorelec, "Datasets for phishing websites
detection", Data in Brief 33 (2020), mirrored at
https://github.com/GregaVrbancic/Phishing-Dataset. FEATURE_ORDER below is
copied verbatim from that dataset's dataset_full.csv header (minus the
trailing 'phishing' label column) — the model needs the columns in exactly
this order.

Two kinds of features:
  * Lexical (~98): pure string-parsing of the URL. Deterministic, no
    network calls. The exact domain/directory/file/params boundary rules
    aren't published anywhere (the paper describing this dataset says only
    that features were "extracted using custom Python code", with no
    released source) — SEGMENT_URL below uses the standard, most common
    interpretation (netloc / path-minus-last-segment / last-path-segment /
    query-string), verified against the dataset's own value *encodings*
    (which are empirically confirmed against dataset_full.csv — e.g.
    qty_params/tld_present_params both use -1 for "no query string", not
    "lookup failed"; qty_nameservers/qty_mx_servers use 0 rather than -1
    for empty). Minor edge-case URLs could compute slightly differently
    than the original training pipeline; the bulk of the signal (char
    counts, lengths) is unambiguous.

    Two encoding conventions were initially gotten wrong and are worth
    calling out because they measurably biased predictions toward
    "Phishing" for ordinary root-URL sites (e.g. "https://github.com"),
    confirmed by comparing computed features against dataset_full.csv's
    own distributions — see test_vrbancic_features.py's
    LexicalFeatureRegressionTests for the regression tests:
      1. directory_length/file_length (and every qty_*_directory/
         qty_*_file char count) must be -1 when the URL has no path
         component at all, not 0 for "empty" — -1 is the dataset's
         "component absent" sentinel, and it accounts for ~54% of all
         rows. directory_length alone is the model's single most
         important feature.
      2. length_url/qty_*_url are measured on the URL with its
         "http://"/"https://" scheme already stripped off — confirmed by
         the "Normal" class having a qty_slash_url mode of 0 and a
         length_url minimum of 4, both impossible if a scheme (7-8 chars,
         2 slashes) were included.

  * Network-derived (13): DNS records, RDAP (domain age/expiration), TLS
    certificate validity, live HTTP response time/redirects, ASN. Each is
    wrapped so a failure/timeout degrades to the same sentinel the dataset
    itself uses for "could not determine" (-1, confirmed empirically —
    e.g. domain_spf/asn_ip/ttl_hostname/time_response range from -1 up,
    with -1 clearly meaning "lookup failed" in real rows) rather than
    crashing the request. url_google_index/domain_google_index are always
    -1 here: reliably checking Google's index means scraping search
    results, which isn't something to automate against Google's ToS — see
    the project discussion for why this was deliberately left unimplemented
    rather than faked with a wrong value the model would trust.
"""

import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import requests
import tldextract

FEATURE_ORDER = [
    "qty_dot_url", "qty_hyphen_url", "qty_underline_url", "qty_slash_url",
    "qty_questionmark_url", "qty_equal_url", "qty_at_url", "qty_and_url",
    "qty_exclamation_url", "qty_space_url", "qty_tilde_url", "qty_comma_url",
    "qty_plus_url", "qty_asterisk_url", "qty_hashtag_url", "qty_dollar_url",
    "qty_percent_url", "qty_tld_url", "length_url",
    "qty_dot_domain", "qty_hyphen_domain", "qty_underline_domain", "qty_slash_domain",
    "qty_questionmark_domain", "qty_equal_domain", "qty_at_domain", "qty_and_domain",
    "qty_exclamation_domain", "qty_space_domain", "qty_tilde_domain", "qty_comma_domain",
    "qty_plus_domain", "qty_asterisk_domain", "qty_hashtag_domain", "qty_dollar_domain",
    "qty_percent_domain", "qty_vowels_domain", "domain_length", "domain_in_ip",
    "server_client_domain",
    "qty_dot_directory", "qty_hyphen_directory", "qty_underline_directory", "qty_slash_directory",
    "qty_questionmark_directory", "qty_equal_directory", "qty_at_directory", "qty_and_directory",
    "qty_exclamation_directory", "qty_space_directory", "qty_tilde_directory", "qty_comma_directory",
    "qty_plus_directory", "qty_asterisk_directory", "qty_hashtag_directory", "qty_dollar_directory",
    "qty_percent_directory", "directory_length",
    "qty_dot_file", "qty_hyphen_file", "qty_underline_file", "qty_slash_file",
    "qty_questionmark_file", "qty_equal_file", "qty_at_file", "qty_and_file",
    "qty_exclamation_file", "qty_space_file", "qty_tilde_file", "qty_comma_file",
    "qty_plus_file", "qty_asterisk_file", "qty_hashtag_file", "qty_dollar_file",
    "qty_percent_file", "file_length",
    "qty_dot_params", "qty_hyphen_params", "qty_underline_params", "qty_slash_params",
    "qty_questionmark_params", "qty_equal_params", "qty_at_params", "qty_and_params",
    "qty_exclamation_params", "qty_space_params", "qty_tilde_params", "qty_comma_params",
    "qty_plus_params", "qty_asterisk_params", "qty_hashtag_params", "qty_dollar_params",
    "qty_percent_params", "params_length", "tld_present_params", "qty_params",
    "email_in_url",
    "time_response", "domain_spf", "asn_ip", "time_domain_activation",
    "time_domain_expiration", "qty_ip_resolved", "qty_nameservers", "qty_mx_servers",
    "ttl_hostname", "tls_ssl_certificate", "qty_redirects", "url_google_index",
    "domain_google_index", "url_shortened",
]
assert len(FEATURE_ORDER) == 111

_SPECIAL_CHARS = ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']
_SPECIAL_CHAR_NAMES = [
    'dot', 'hyphen', 'underline', 'slash', 'questionmark', 'equal', 'at', 'and',
    'exclamation', 'space', 'tilde', 'comma', 'plus', 'asterisk', 'hashtag', 'dollar', 'percent',
]

# A working (not exhaustive) list of TLDs, used only for the low-importance
# qty_tld_url / tld_present_params heuristics.
_COMMON_TLDS = [
    'com', 'net', 'org', 'info', 'biz', 'edu', 'gov', 'mil', 'io', 'co',
    'me', 'tv', 'cc', 'xyz', 'top', 'club', 'online', 'site', 'shop', 'app',
    'dev', 'ru', 'cn', 'uk', 'de', 'fr', 'br', 'in', 'jp', 'us', 'ca', 'au',
    'nl', 'es', 'it', 'pl', 'se', 'no', 'za', 'mx', 'ar', 'ng', 'ke', 'gh',
]

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly", "bl.ink", "tiny.cc",
}

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

NETWORK_TIMEOUT_SECONDS = 5


def registrable_domain(host):
    """
    "www.google.com" -> "google.com", "accounts.google.co.uk" ->
    "google.co.uk". Records like NS/MX/SPF and the domain's WHOIS/RDAP
    registration live at this level, not on an arbitrary subdomain — an NS
    or SPF lookup on "www.google.com" itself typically comes back empty
    even though google.com plainly has both, which without this produced a
    false "no nameservers / no SPF / unknown domain age" signal for
    completely ordinary sites. A/TLS/HTTP checks stay on the full hostname
    below since those are legitimately per-host.
    """
    ext = tldextract.extract(host)
    return ext.registered_domain or host


def _char_counts(prefix, text):
    return {f"qty_{name}_{prefix}": text.count(ch) for name, ch in zip(_SPECIAL_CHAR_NAMES, _SPECIAL_CHARS)}


def segment_url(url):
    """
    Splits a URL into (domain, directory, file, params) substrings.

    directory/file come back as None when the URL has no path beyond the
    domain at all (e.g. "https://github.com" or "https://github.com/").
    That's deliberate: in the source dataset, "no directory/file component"
    is encoded as -1 across every directory_*/file_* feature, not 0 -- and
    it's the single most common case (~54% of all 88,647 rows) *and*
    directory_length is the model's single most important feature by a
    wide margin. An earlier version of this function returned "" in that
    case, which extract_lexical_features then measured as length 0 --
    indistinguishable from "a directory that happens to be empty", instead
    of "no directory at all". That collapsed the dataset's strongest
    signal and was the main reason plain root-URL sites like
    "https://github.com" were scored as phishing: confirmed by comparing
    against directory_length's distribution in dataset_full.csv, where the
    -1 sentinel accounts for the entire mass of the "Normal" class
    (median -1) while present-and-long directories skew heavily
    "Phishing" (median 23).
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.netloc
    path = parsed.path or ""
    if path in ("", "/"):
        return domain, None, None, parsed.query or ""
    last_slash = path.rfind("/")
    if last_slash == -1:
        directory, file_part = "", path
    else:
        directory, file_part = path[:last_slash + 1], path[last_slash + 1:]
    params = parsed.query or ""
    return domain, directory, file_part, params


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def extract_lexical_features(url):
    domain, directory, file_part, params = segment_url(url)
    features = {}

    # The dataset's own *_url features (length_url, qty_slash_url, etc.)
    # are measured on the URL with its "http://"/"https://" scheme
    # stripped off -- confirmed empirically: 80% of the "Normal" class has
    # qty_slash_url == 0 and length_url has a min of 4, both impossible if
    # a scheme (which alone contributes 2 slashes and 7-8 characters) were
    # included. Measuring the raw `url` (scheme included) instead
    # systematically inflated length_url and qty_slash_url for every
    # top-level site -- e.g. "https://github.com" scored qty_slash_url=2
    # against a Normal-class median of 0 -- and was a major contributor to
    # well-known sites being scored as phishing.
    url_for_features = _SCHEME_RE.sub("", url)

    features.update(_char_counts('url', url_for_features))
    features['qty_tld_url'] = sum(url_for_features.lower().count(f".{tld}") for tld in _COMMON_TLDS)
    features['length_url'] = len(url_for_features)

    features.update(_char_counts('domain', domain))
    features['qty_vowels_domain'] = sum(domain.lower().count(v) for v in 'aeiou')
    features['domain_length'] = len(domain)
    host_only = domain.split(':')[0]
    features['domain_in_ip'] = int(bool(_IPV4_RE.match(host_only)))
    features['server_client_domain'] = int('server' in domain.lower() or 'client' in domain.lower())

    if directory is None:
        # No path at all: matches the dataset's "-1 = component absent"
        # convention (see segment_url's docstring), not "empty directory".
        for name in _SPECIAL_CHAR_NAMES:
            features[f'qty_{name}_directory'] = -1
        features['directory_length'] = -1
    else:
        features.update(_char_counts('directory', directory))
        features['directory_length'] = len(directory)

    if file_part is None:
        for name in _SPECIAL_CHAR_NAMES:
            features[f'qty_{name}_file'] = -1
        features['file_length'] = -1
    else:
        features.update(_char_counts('file', file_part))
        features['file_length'] = len(file_part)

    features.update(_char_counts('params', params))
    features['params_length'] = len(params)
    if params:
        features['tld_present_params'] = int(any(f".{tld}" in params.lower() for tld in _COMMON_TLDS))
        features['qty_params'] = params.count('&') + 1
    else:
        # Matches the dataset's own convention: -1 means "no query string
        # at all", not "lookup failed" (there's nothing to look up).
        features['tld_present_params'] = -1
        features['qty_params'] = -1

    features['email_in_url'] = int(bool(_EMAIL_RE.search(url)))
    features['url_shortened'] = int(host_only.lower() in _SHORTENERS)

    return features


# --- Network-derived features -------------------------------------------

def _lookup_time_response_and_redirects(url):
    try:
        start = time.monotonic()
        response = requests.get(url, timeout=NETWORK_TIMEOUT_SECONDS, allow_redirects=True)
        elapsed = time.monotonic() - start
        return {'time_response': round(elapsed, 6), 'qty_redirects': len(response.history)}
    except Exception:
        return {'time_response': -1.0, 'qty_redirects': -1}


def _lookup_dns_a(host):
    try:
        answer = dns.resolver.resolve(host, 'A', lifetime=NETWORK_TIMEOUT_SECONDS)
        ips = [r.address for r in answer]
        return {'qty_ip_resolved': len(ips), 'ttl_hostname': answer.rrset.ttl, '_first_ip': ips[0] if ips else None}
    except Exception:
        return {'qty_ip_resolved': -1, 'ttl_hostname': -1, '_first_ip': None}


def _lookup_dns_ns(host):
    try:
        answer = dns.resolver.resolve(host, 'NS', lifetime=NETWORK_TIMEOUT_SECONDS)
        return {'qty_nameservers': len(list(answer))}
    except Exception:
        return {'qty_nameservers': 0}


def _lookup_dns_mx(host):
    try:
        answer = dns.resolver.resolve(host, 'MX', lifetime=NETWORK_TIMEOUT_SECONDS)
        return {'qty_mx_servers': len(list(answer))}
    except Exception:
        return {'qty_mx_servers': 0}


def _lookup_spf(host):
    try:
        answer = dns.resolver.resolve(host, 'TXT', lifetime=NETWORK_TIMEOUT_SECONDS)
        has_spf = any('v=spf1' in b''.join(r.strings).decode('utf-8', 'ignore').lower() for r in answer)
        return {'domain_spf': int(has_spf)}
    except Exception:
        return {'domain_spf': -1}


def _lookup_asn(ip):
    if not ip:
        return {'asn_ip': -1}
    try:
        reversed_ip = '.'.join(reversed(ip.split('.')))
        query = f'{reversed_ip}.origin.asn.cymru.com'
        answer = dns.resolver.resolve(query, 'TXT', lifetime=NETWORK_TIMEOUT_SECONDS)
        text = b''.join(answer[0].strings).decode('utf-8', 'ignore')
        asn = int(text.split('|')[0].strip().split(' ')[0])
        return {'asn_ip': asn}
    except Exception:
        return {'asn_ip': -1}


def _lookup_rdap(host):
    try:
        response = requests.get(f'https://rdap.org/domain/{host}', timeout=NETWORK_TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()
        events = {e.get('eventAction'): e.get('eventDate') for e in data.get('events', [])}
        now = datetime.now(timezone.utc)

        def days_from(date_str):
            if not date_str:
                return -1
            try:
                dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                return (now - dt).days
            except Exception:
                return -1

        activation = days_from(events.get('registration'))
        expiration_date = events.get('expiration')
        expiration = -1
        if expiration_date:
            try:
                dt = datetime.fromisoformat(expiration_date.replace('Z', '+00:00'))
                expiration = (dt - now).days
            except Exception:
                expiration = -1
        return {'time_domain_activation': activation, 'time_domain_expiration': expiration}
    except Exception:
        return {'time_domain_activation': -1, 'time_domain_expiration': -1}


def _lookup_tls(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=NETWORK_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_sock.getpeercert()  # raises if invalid/untrusted
        return {'tls_ssl_certificate': 1}
    except Exception:
        return {'tls_ssl_certificate': 0}


def extract_network_features(url, timeout=None):
    """
    Runs every network lookup concurrently (they're independent I/O calls)
    and merges the results. Each lookup degrades to the dataset's own
    "unavailable" sentinel on failure/timeout rather than raising, so a
    single flaky lookup never fails the whole prediction.
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").strip()
    if not host:
        return {name: (-1.0 if name == 'time_response' else -1) for name in (
            'time_response', 'domain_spf', 'asn_ip', 'time_domain_activation',
            'time_domain_expiration', 'qty_ip_resolved', 'qty_nameservers',
            'qty_mx_servers', 'ttl_hostname', 'tls_ssl_certificate', 'qty_redirects',
        )}
    base_domain = registrable_domain(host)

    jobs = {
        'response': lambda: _lookup_time_response_and_redirects(url),
        'a': lambda: _lookup_dns_a(host),
        'ns': lambda: _lookup_dns_ns(base_domain),
        'mx': lambda: _lookup_dns_mx(base_domain),
        'spf': lambda: _lookup_spf(base_domain),
        'rdap': lambda: _lookup_rdap(base_domain),
        'tls': lambda: _lookup_tls(host),
    }

    results = {}
    per_job_timeout = timeout or (NETWORK_TIMEOUT_SECONDS + 2)
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {name: pool.submit(fn) for name, fn in jobs.items()}
        for name, future in futures.items():
            try:
                results[name] = future.result(timeout=per_job_timeout)
            except (FutureTimeoutError, Exception):
                results[name] = {}

    merged = {}
    for part in results.values():
        merged.update(part)

    first_ip = merged.pop('_first_ip', None)
    merged.update(_lookup_asn(first_ip))

    # Deliberately not implemented: checking Google's index means scraping
    # search results, which isn't something to automate against Google's
    # ToS. -1 matches the dataset's own "could not determine" convention.
    merged.setdefault('url_google_index', -1)
    merged.setdefault('domain_google_index', -1)

    for key, default in [
        ('time_response', -1.0), ('domain_spf', -1), ('asn_ip', -1),
        ('time_domain_activation', -1), ('time_domain_expiration', -1),
        ('qty_ip_resolved', -1), ('qty_nameservers', 0), ('qty_mx_servers', 0),
        ('ttl_hostname', -1), ('tls_ssl_certificate', 0), ('qty_redirects', -1),
    ]:
        merged.setdefault(key, default)

    return merged


def extract_all_features(url, include_network=True):
    features = extract_lexical_features(url)
    if include_network:
        features.update(extract_network_features(url))
    else:
        for key in [
            'time_response', 'domain_spf', 'asn_ip', 'time_domain_activation',
            'time_domain_expiration', 'qty_ip_resolved', 'qty_nameservers',
            'qty_mx_servers', 'ttl_hostname', 'tls_ssl_certificate', 'qty_redirects',
            'url_google_index', 'domain_google_index',
        ]:
            features.setdefault(key, -1)
    return features


def to_feature_vector(features):
    """Orders a features dict into the exact 111-length list the model expects."""
    return [features[name] for name in FEATURE_ORDER]
