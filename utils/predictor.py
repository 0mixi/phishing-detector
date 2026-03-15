"""
Predictor — Rule-weighted scoring model for phishing classification.

Uses a weighted scoring system based on the 18 extracted features.
Run `python model/train.py` to train a full Random Forest model and
replace this scorer with the trained model for higher accuracy.
"""

from utils.extractor import extract_features

# Feature weights — higher = stronger phishing signal
WEIGHTS = {
    "has_ip":             10,
    "has_at_symbol":      10,
    "brand_in_subdomain":  9,
    "has_suspicious_tld":  8,
    "has_hex_encoding":    7,
    "has_double_slash":    6,
    "keyword_count":       5,   # multiplied by count
    "hyphen_count":        3,   # multiplied by count
    "subdomain_depth":     4,   # multiplied by depth
    "has_port":            5,
    "domain_has_digits":   3,
    "long_path":           3,
    "special_char_ratio":  8,   # multiplied by ratio
    "url_length":          0,   # handled separately
    "dot_count":           2,   # multiplied by count
    "uses_https":         -4,   # negative = reduces score
    "path_depth":          1,
    "domain_length":       0,   # handled separately
}

THRESHOLD = 18  # Score at or above this = phishing

def score(features: dict) -> float:
    s = 0
    s += WEIGHTS["has_ip"]             * int(features["has_ip"])
    s += WEIGHTS["has_at_symbol"]      * int(features["has_at_symbol"])
    s += WEIGHTS["brand_in_subdomain"] * int(features["brand_in_subdomain"])
    s += WEIGHTS["has_suspicious_tld"] * int(features["has_suspicious_tld"])
    s += WEIGHTS["has_hex_encoding"]   * int(features["has_hex_encoding"])
    s += WEIGHTS["has_double_slash"]   * int(features["has_double_slash"])
    s += WEIGHTS["has_port"]           * int(features["has_port"])
    s += WEIGHTS["domain_has_digits"]  * int(features["domain_has_digits"])
    s += WEIGHTS["long_path"]          * int(features["long_path"])
    s += WEIGHTS["uses_https"]         * int(features["uses_https"])
    s += WEIGHTS["keyword_count"]      * min(features["keyword_count"], 4)
    s += WEIGHTS["hyphen_count"]       * min(features["hyphen_count"], 4)
    s += WEIGHTS["subdomain_depth"]    * min(features["subdomain_depth"], 3)
    s += WEIGHTS["special_char_ratio"] * features["special_char_ratio"]
    s += WEIGHTS["dot_count"]          * max(0, features["dot_count"] - 2)
    s += WEIGHTS["path_depth"]         * max(0, features["path_depth"] - 3)
    # Long URLs are a weak phishing signal
    if features["url_length"] > 75:
        s += 3
    if features["url_length"] > 120:
        s += 4
    return s

def score_to_confidence(s: float) -> float:
    """Map raw score to a 0–1 confidence value using a sigmoid-like curve."""
    import math
    # Normalise around the threshold
    x = (s - THRESHOLD) / 10
    return round(1 / (1 + math.exp(-x)), 3)

def predict(url: str, features: dict) -> dict:
    raw_score  = score(features)
    confidence = score_to_confidence(raw_score)
    is_phishing = raw_score >= THRESHOLD

    # Build human-readable risk factors
    risk_factors = []
    if features["has_ip"]:            risk_factors.append("IP address used as domain")
    if features["has_at_symbol"]:     risk_factors.append("@ symbol in URL (redirect trick)")
    if features["brand_in_subdomain"]: risk_factors.append("Brand name in subdomain (spoofing)")
    if features["has_suspicious_tld"]: risk_factors.append("Suspicious free TLD")
    if features["has_hex_encoding"]:  risk_factors.append("Hex-encoded characters")
    if features["keyword_count"] >= 2: risk_factors.append(f"{features['keyword_count']} phishing keywords")
    if features["hyphen_count"] >= 3: risk_factors.append(f"Excessive hyphens ({features['hyphen_count']})")
    if features["subdomain_depth"] >= 3: risk_factors.append(f"Deep subdomain nesting ({features['subdomain_depth']})")
    if not features["uses_https"]:    risk_factors.append("No HTTPS")
    if features["has_double_slash"]:  risk_factors.append("Double slash in path")
    if features["long_path"]:         risk_factors.append("Unusually long path")

    return {
        "url":         url,
        "is_phishing": is_phishing,
        "confidence":  confidence,
        "raw_score":   round(raw_score, 2),
        "label":       "PHISHING" if is_phishing else "SAFE",
        "risk_factors": risk_factors,
        "features":    features,
    }
