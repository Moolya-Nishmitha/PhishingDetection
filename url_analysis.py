import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".click"]
TRUSTED_DOMAINS = ["google.com", "github.com", "microsoft.com", "apple.com", "amazon.com"]

def analyze_url(url: str) -> dict:
    score = 0
    reasons = []

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()

    if len(url) > 75:
        score += 1
        reasons.append(f"Unusually long URL ({len(url)} chars)")

    if parsed.scheme == "http":
        score += 1
        reasons.append("Uses HTTP instead of HTTPS")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc):
        score += 2
        reasons.append("IP address used instead of domain name")

    if "@" in url:
        score += 2
        reasons.append("@ symbol in URL (browser ignores everything before it)")

    if netloc.count(".") > 3:
        score += 1
        reasons.append(f"Too many subdomains ({netloc.count('.')} dots)")

    for tld in SUSPICIOUS_TLDS:
        if netloc.endswith(tld):
            score += 1
            reasons.append(f"Suspicious TLD: {tld}")
            break

    if "-" in netloc:
        score += 1
        reasons.append("Hyphen in domain (common spoofing pattern)")

    misleading = ["secure", "login", "verify", "update", "bank", "paypal", "account"]
    for word in misleading:
        if word in netloc:
            score += 1
            reasons.append(f"Misleading keyword in domain: '{word}'")
            break

    for domain in TRUSTED_DOMAINS:
        if domain in netloc and not netloc.endswith(domain):
            score += 2
            reasons.append(f"Impersonating '{domain}'")
            break

    return {"score": score, "reasons": reasons}