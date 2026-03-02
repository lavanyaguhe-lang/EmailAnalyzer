import math
import re
from urllib.parse import urlparse

from textblob import TextBlob


def _rule_based_score(content, url_input):
    lowered = content.lower()
    score = 0
    reasons = []
    suspicious_feature_hits = 0

    weighted_triggers = {
        "verify your account": 35,
        "click here": 25,
        "free cash": 25,
        "lottery": 20,
        "inheritance": 25,
        "urgent": 10,
        "unusual activity": 22,
        "suspicious activity": 22,
        "action required": 15,
        "account suspended": 25,
        "account locked": 22,
        "change your password": 18,
        "password": 5,
        "password reset": 15,
        "bank": 6,
        "wire transfer": 20,
        "crypto": 15,
        "gift card": 20,
        "otp": 12,
    }

    benign_markers = {
        "meeting": 6,
        "schedule": 6,
        "minutes": 5,
        "attached": 5,
        "regards": 5,
        "thanks": 4,
        "invoice": 6,
        "agenda": 6,
        "project update": 7,
        "approved": 5,
        "as discussed": 5,
    }

    matched_triggers = set()
    for phrase, weight in weighted_triggers.items():
        if phrase in lowered:
            score += weight
            reasons.append(f"Matched '{phrase}'")
            matched_triggers.add(phrase)

    for phrase, weight in benign_markers.items():
        if phrase in lowered:
            score -= weight

    url_count = lowered.count("http://") + lowered.count("https://")
    if url_count >= 2:
        score += 18
        reasons.append("Multiple URLs detected")
    elif url_count == 1:
        score += 8

    if content.isupper() and len(content) > 25:
        score += 12
        reasons.append("All-caps text detected")
        suspicious_feature_hits += 1

    url = (url_input or "").strip().lower()
    if url:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = parsed.netloc or parsed.path
        host = host.split(":")[0]
        url_suspicious = 0

        if parsed.scheme == "http":
            score += 12
            url_suspicious += 1
            reasons.append("Non-HTTPS URL")

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            score += 30
            url_suspicious += 1
            reasons.append("IP-based URL")
        if "@" in url:
            score += 25
            url_suspicious += 1
            reasons.append("@ found in URL")
        if "--" in host or "xn--" in host:
            score += 20
            url_suspicious += 1
            reasons.append("Potential lookalike domain")
        for shortener in ("bit.ly", "tinyurl.com", "t.co", "rb.gy"):
            if shortener in host:
                score += 25
                url_suspicious += 1
                reasons.append("Shortened URL")
                break
        if len(url) > 120:
            score += 10
            url_suspicious += 1
            reasons.append("Very long URL")
        if host.count(".") >= 3:
            score += 8
            url_suspicious += 1
            reasons.append("Many subdomains")
        if re.search(r"\d{3,}", host):
            score += 8
            url_suspicious += 1
            reasons.append("Digit-heavy host")
        risky_tlds = (".zip", ".top", ".xyz", ".click", ".work", ".support")
        if host.endswith(risky_tlds):
            score += 15
            url_suspicious += 1
            reasons.append("Risky TLD")

        # Trusted exact or parent domains reduce false positives.
        trusted_domains = (
            "microsoft.com",
            "google.com",
            "apple.com",
            "amazon.com",
            "github.com",
            "linkedin.com",
            "adobe.com",
            "dropbox.com",
        )
        if any(host == d or host.endswith(f".{d}") for d in trusted_domains) and url_suspicious == 0:
            score -= 10
        elif parsed.scheme == "https" and url_suspicious == 0:
            score -= 6

        suspicious_feature_hits += url_suspicious

    # Combo rules catch typical phishing pattern clusters.
    has_credential_lure = any(k in matched_triggers for k in ("verify your account", "password reset", "otp", "account locked"))
    has_urgency = any(k in matched_triggers for k in ("urgent", "action required", "account suspended", "unusual activity", "suspicious activity"))
    has_click_cta = any(k in matched_triggers for k in ("click here", "verify your account"))
    if has_credential_lure and has_urgency:
        score += 10
    if has_click_cta and suspicious_feature_hits > 0:
        score += 12

    return score, reasons, suspicious_feature_hits


def _ml_probability(content, polarity, suspicious_feature_hits):
    # Lightweight ML-style score using tokenized features + sentiment.
    lowered = content.lower()
    token_count = max(1, len(lowered.split()))
    urgent_hits = sum(1 for k in ("urgent", "now", "immediately", "asap") if k in lowered)
    credential_hits = sum(1 for k in ("password", "otp", "login", "verify", "account") if k in lowered)
    money_hits = sum(1 for k in ("gift card", "transfer", "crypto", "bank", "cash") if k in lowered)
    exclamations = lowered.count("!")

    linear = (
        -1.2
        + (urgent_hits * 0.65)
        + (credential_hits * 0.55)
        + (money_hits * 0.6)
        + (exclamations * 0.08)
        + max(0.0, -polarity) * 1.6
        + (suspicious_feature_hits * 0.55)
        + (token_count < 8) * 0.55
    )
    return 1.0 / (1.0 + math.exp(-linear))


def analyze_email_text(text, url_input=""):
    try:
        content = (text or "").strip()
        url_text = (url_input or "").strip()
        combined = f"{content} {url_text}".strip()

        blob = TextBlob(combined)
        polarity = blob.sentiment.polarity

        if polarity > 0.1:
            sentiment = "Positive / Professional"
        elif polarity < -0.1:
            sentiment = "Negative / Aggressive"
        else:
            sentiment = "Neutral / Objective"

        rule_score, reasons, suspicious_feature_hits = _rule_based_score(combined, url_text)
        ml_prob = _ml_probability(combined, polarity, suspicious_feature_hits)
        ml_score = int(ml_prob * 100)

        risk_score = int((rule_score * 0.65) + (ml_score * 0.35))
        risk_score = max(0, min(100, risk_score))
        is_spam = risk_score >= 35

        explanation = "; ".join(reasons[:3]) if reasons else "No strong phishing indicators detected"

        return {
            'sentiment': sentiment,
            'is_spam': "Yes (High Risk)" if is_spam else "No (Safe)",
            'score': round(polarity, 2),
            'risk_score': risk_score,
            'explanation': explanation,
            'ml_score': ml_score,
        }

    except Exception as e:
        print(f"Analysis Error: {e}")
        return {
            'sentiment': "Error in Analysis",
            'is_spam': "Unknown",
            'score': 0,
            'risk_score': 0,
            'explanation': "Analysis failed",
            'ml_score': 0,
        }
