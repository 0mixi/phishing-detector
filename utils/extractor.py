"""
Feature Extractor
Extracts 18 handcrafted features from a URL for phishing classification.
"""

import re
from urllib.parse import urlparse

# Known legitimate TLDs that phishers rarely use as the primary domain
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link", ".work"}

# Keywords commonly found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "signin", "secure", "account", "update", "verify",
    "banking", "paypal", "amazon", "apple", "microsoft", "google",
    "password", "credential", "confirm", "suspend", "unusual",
    "unlock", "validate", "authenticate", "support", "help-center",
]

# Trusted brands that are commonly spoofed
BRAND_NAMES = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hdfc",
    "sbi", "icici", "axis",
]

IP_PATTERN   = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
AT_PATTERN   = re.compile(r"@")
HEX_PATTERN  = re.compile(r"%[0-9a-fA-F]{2}")


def extract_features(url: str) -> dict:
    """Extract 18 features from a URL string."""
    try:
        parsed   = urlparse(url if url.startswith("http") else "http://" + url)
        domain   = parsed.netloc.lower()
        path     = parsed.path.lower()
        full_url = url.lower()
    except Exception:
        return _empty_features()

    # 1. URL length
    url_length = len(url)

    # 2. Domain length
    domain_length = len(domain)

    # 3. Number of dots in domain
    dot_count = domain.count(".")

    # 4. Number of hyphens in domain
    hyphen_count = domain.count("-")

    # 5. Has IP address as domain
    has_ip = bool(IP_PATTERN.search(domain))

    # 6. Has @ symbol (redirects to different host)
    has_at_symbol = bool(AT_PATTERN.search(url))

    # 7. Uses HTTPS
    uses_https = url.lower().startswith("https")

    # 8. Subdomain depth (number of dots before main domain)
    subdomain_depth = max(0, domain.count(".") - 1)

    # 9. Suspicious TLD
    tld = "." + domain.split(".")[-1] if "." in domain else ""
    has_suspicious_tld = tld in SUSPICIOUS_TLDS

    # 10. Phishing keyword count
    keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in full_url)

    # 11. Brand name in subdomain/path (NOT as main domain — spoofing indicator)
    main_domain_parts = domain.split(".")
    main_domain_name  = main_domain_parts[-2] if len(main_domain_parts) >= 2 else domain
    brand_in_subdomain = any(
        brand in domain and brand != main_domain_name
        for brand in BRAND_NAMES
    )

    # 12. Special character ratio
    special_chars   = re.findall(r"[^a-zA-Z0-9./:_-]", url)
    special_char_ratio = len(special_chars) / max(len(url), 1)

    # 13. Hex encoding present
    has_hex_encoding = bool(HEX_PATTERN.search(url))

    # 14. Path depth
    path_depth = len([p for p in path.split("/") if p])

    # 15. Has port number
    has_port = bool(parsed.port and parsed.port not in (80, 443))

    # 16. URL contains double slash (redirect trick)
    has_double_slash = "//" in parsed.path

    # 17. Domain contains numbers
    domain_has_digits = bool(re.search(r"\d", main_domain_name))

    # 18. Extremely long path
    long_path = len(path) > 100

    return {
        "url_length":          url_length,
        "domain_length":       domain_length,
        "dot_count":           dot_count,
        "hyphen_count":        hyphen_count,
        "has_ip":              has_ip,
        "has_at_symbol":       has_at_symbol,
        "uses_https":          uses_https,
        "subdomain_depth":     subdomain_depth,
        "has_suspicious_tld":  has_suspicious_tld,
        "keyword_count":       keyword_count,
        "brand_in_subdomain":  brand_in_subdomain,
        "special_char_ratio":  round(special_char_ratio, 3),
        "has_hex_encoding":    has_hex_encoding,
        "path_depth":          path_depth,
        "has_port":            has_port,
        "has_double_slash":    has_double_slash,
        "domain_has_digits":   domain_has_digits,
        "long_path":           long_path,
    }

def _empty_features() -> dict:
    return {k: 0 for k in [
        "url_length", "domain_length", "dot_count", "hyphen_count",
        "has_ip", "has_at_symbol", "uses_https", "subdomain_depth",
        "has_suspicious_tld", "keyword_count", "brand_in_subdomain",
        "special_char_ratio", "has_hex_encoding", "path_depth",
        "has_port", "has_double_slash", "domain_has_digits", "long_path"
    ]}
