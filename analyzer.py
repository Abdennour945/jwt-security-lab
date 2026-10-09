import base64
import json
from checks import run_security_checks


def decode_base64url(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def analyze_token(token: str) -> dict:
    token = token.strip()
    parts = token.split(".")

    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    try:
        header = json.loads(decode_base64url(parts[0]))
        payload = json.loads(decode_base64url(parts[1]))
    except Exception as exc:
        raise ValueError("Token decoding failed") from exc

    findings = run_security_checks(header, payload)

    severity_weights = {
        "info": 5,
        "warning": 15,
        "high": 30,
        "critical": 45
    }

    risk_score = min(
        100,
        sum(severity_weights.get(f["severity"], 0) for f in findings)
    )

    if risk_score >= 80:
        summary = "Critical JWT security issues detected"
    elif risk_score >= 40:
        summary = "Multiple JWT security issues detected"
    elif risk_score > 0:
        summary = "Some JWT security issues detected"
    else:
        summary = "No obvious JWT security issues detected"

    return {
        "header": header,
        "payload": payload,
        "signature": parts[2],
        "findings": findings,
        "risk_score": risk_score,
        "summary": summary
    }