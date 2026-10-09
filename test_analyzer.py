from analyzer import analyze_token
import pytest


def test_invalid_format():
    with pytest.raises(ValueError, match="Invalid JWT format"):
        analyze_token("abc.def")


def test_alg_none_detected():
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ."
    result = analyze_token(token)

    issues = [finding["issue"] for finding in result["findings"]]
    assert any("alg=none" in issue for issue in issues)


def test_missing_exp_detected():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"
    result = analyze_token(token)

    issues = [finding["issue"] for finding in result["findings"]]
    assert any("exp claim missing" in issue for issue in issues)


def test_sensitive_payload_detected():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJwYXNzd29yZCI6IjEyMzQ1NiJ9.signature"
    result = analyze_token(token)

    issues = [finding["issue"] for finding in result["findings"]]
    assert any("Sensitive data detected" in issue for issue in issues)


def test_valid_like_token_returns_result():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJleHAiOjQ3MDAwMDAwMDB9.signature"
    result = analyze_token(token)

    assert "header" in result
    assert "payload" in result
    assert "findings" in result
    assert "risk_score" in result
    assert result["header"]["alg"] == "HS256"