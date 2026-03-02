import re

PHISHING_KEYWORDS = [
    "urgent", "verify", "click here", "login", "password",
    "bank", "account suspended", "lottery", "win", "prize",
    "update immediately", "security alert", "confirm your details",
    "limited time", "act now", "you have been selected",
    "dear customer", "your account will be", "unusual activity"
]

def analyze_content(text: str) -> dict:
    score = 0
    found_keywords = []
    text_lower = text.lower()

    for keyword in PHISHING_KEYWORDS:
        if keyword in text_lower:
            score += 1
            found_keywords.append(keyword)

    # Excessive exclamation marks
    exclamation_count = text.count("!")
    if exclamation_count > 3:
        score += 1

    # ALL CAPS words (scare tactics)
    caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
    if caps_words:
        score += 1

    # Requests for sensitive info
    sensitive = ["credit card", "social security", "ssn", "cvv", "pin number", "date of birth"]
    for term in sensitive:
        if term in text_lower:
            score += 2
            found_keywords.append(f"sensitive info request: '{term}'")

    # Generic greeting (phishing often avoids your real name)
    if re.search(r'\bdear (customer|user|member|account holder)\b', text_lower):
        score += 1
        found_keywords.append("generic greeting (no name used)")

    return {"score": score, "keywords_found": found_keywords}