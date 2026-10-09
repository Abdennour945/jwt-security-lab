import time


def run_security_checks(header: dict, payload: dict) -> list:
    findings = []

    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        findings.append({
            "severity": "critical",
            "issue": "alg=none detected (unsigned token)"
        })

    if "exp" not in payload:
        findings.append({
            "severity": "warning",
            "issue": "Token has no expiration (exp claim missing)"
        })

    if "exp" in payload and isinstance(payload["exp"], (int, float)):
        if payload["exp"] < int(time.time()):
            findings.append({
                "severity": "high",
                "issue": "Token is expired"
            })

    if "jku" in header or "x5u" in header:
        findings.append({
            "severity": "high",
            "issue": "Token references remote key (jku/x5u)"
        })

    sensitive_fields = ["password", "secret", "apikey", "api_key"]

    for field in payload:
        if field.lower() in sensitive_fields:
            findings.append({
                "severity": "warning",
                "issue": f"Sensitive data detected in payload: {field}"
            })

    return findings