#!/usr/bin/env python3
"""
Integration tests for the Email Security API.

Run with: python tests/test_api.py
Or with pytest: pytest tests/test_api.py -v
"""

import json
import sys
from pathlib import Path

import httpx
import pytest

pytestmark = pytest.mark.integration

API_URL = "http://localhost:8000"
TEST_EMAILS_DIR = Path(__file__).parent / "test_emails"


def load_test_email(filename: str) -> dict:
    """Load a test email from JSON file."""
    filepath = TEST_EMAILS_DIR / filename
    with open(filepath) as f:
        return json.load(f)


def test_health_endpoint():
    """Test the health endpoint."""
    print("\n[TEST] Health endpoint...")
    response = httpx.get(f"{API_URL}/health", timeout=10.0)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    print(f"  Status: {data['status']}")
    print(f"  Ollama: {data['ollama_connected']}")
    print(f"  Qdrant: {data['qdrant_connected']}")
    print(f"  Models: {data['models_loaded']}")
    assert data["status"] in ["healthy", "degraded"]
    print("  [PASS]")


def test_stats_endpoint():
    """Test the stats endpoint."""
    print("\n[TEST] Stats endpoint...")
    response = httpx.get(f"{API_URL}/api/v1/stats", timeout=10.0)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    print(f"  Threat patterns loaded: {data['threat_patterns_loaded']}")
    print(f"  LLM model: {data['llm_model']}")
    print("  [PASS]")


def test_safe_email():
    """Test analysis of a safe email."""
    print("\n[TEST] Safe email analysis...")
    email = load_test_email("safe_email.json")
    response = httpx.post(
        f"{API_URL}/api/v1/analyze",
        json=email,
        timeout=60.0,
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    print(f"  Verdict: {data['verdict']}")
    print(f"  Confidence: {data['confidence']}")
    print(f"  Threats detected: {len(data['threats_detected'])}")
    print(f"  Processing time: {data['processing_time_ms']:.0f}ms")
    assert data["verdict"] == "safe", f"Expected 'safe', got '{data['verdict']}'"
    print("  [PASS]")


def test_phishing_email():
    """Test analysis of a phishing email."""
    print("\n[TEST] Phishing email analysis...")
    email = load_test_email("phishing_email.json")
    response = httpx.post(
        f"{API_URL}/api/v1/analyze",
        json=email,
        timeout=60.0,
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    print(f"  Verdict: {data['verdict']}")
    print(f"  Confidence: {data['confidence']}")
    print(f"  Threats detected: {len(data['threats_detected'])}")
    for threat in data["threats_detected"][:3]:
        print(f"    - [{threat['threat_type']}] {threat['indicator']}")
    print(f"  Processing time: {data['processing_time_ms']:.0f}ms")
    assert data["verdict"] in ["suspicious", "quarantine"], f"Expected suspicious/quarantine, got '{data['verdict']}'"
    print("  [PASS]")


def test_malware_email():
    """Test analysis of an email with malware attachment."""
    print("\n[TEST] Malware email analysis...")
    email = load_test_email("malware_email.json")
    response = httpx.post(
        f"{API_URL}/api/v1/analyze",
        json=email,
        timeout=60.0,
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    print(f"  Verdict: {data['verdict']}")
    print(f"  Confidence: {data['confidence']}")
    print(f"  Threats detected: {len(data['threats_detected'])}")
    for threat in data["threats_detected"][:3]:
        print(f"    - [{threat['threat_type']}] {threat['indicator']}")
    print(f"  Processing time: {data['processing_time_ms']:.0f}ms")
    assert data["verdict"] == "quarantine", f"Expected 'quarantine', got '{data['verdict']}'"
    print("  [PASS]")


def test_bec_email():
    """Test analysis of a business email compromise attempt."""
    print("\n[TEST] BEC email analysis...")
    email = load_test_email("bec_email.json")
    response = httpx.post(
        f"{API_URL}/api/v1/analyze",
        json=email,
        timeout=60.0,
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    print(f"  Verdict: {data['verdict']}")
    print(f"  Confidence: {data['confidence']}")
    print(f"  Threats detected: {len(data['threats_detected'])}")
    for threat in data["threats_detected"][:3]:
        print(f"    - [{threat['threat_type']}] {threat['indicator']}")
    print(f"  Explanation: {data['explanation'][:100]}...")
    print(f"  Processing time: {data['processing_time_ms']:.0f}ms")
    assert data["verdict"] in ["suspicious", "quarantine"], f"Expected suspicious/quarantine, got '{data['verdict']}'"
    print("  [PASS]")


def test_suspicious_email():
    """Test analysis of a suspicious but not definitively malicious email."""
    print("\n[TEST] Suspicious email analysis...")
    email = load_test_email("suspicious_email.json")
    response = httpx.post(
        f"{API_URL}/api/v1/analyze",
        json=email,
        timeout=60.0,
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    print(f"  Verdict: {data['verdict']}")
    print(f"  Confidence: {data['confidence']}")
    print(f"  Threats detected: {len(data['threats_detected'])}")
    for threat in data["threats_detected"][:3]:
        print(f"    - [{threat['threat_type']}] {threat['indicator']}")
    print(f"  Processing time: {data['processing_time_ms']:.0f}ms")
    assert data["verdict"] in ["suspicious", "quarantine"], f"Expected suspicious/quarantine, got '{data['verdict']}'"
    print("  [PASS]")


def run_all_tests():
    """Run all integration tests."""
    print("=" * 60)
    print("Email Security API - Integration Tests")
    print("=" * 60)

    tests = [
        test_health_endpoint,
        test_stats_endpoint,
        test_safe_email,
        test_phishing_email,
        test_malware_email,
        test_bec_email,
        test_suspicious_email,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {e}")
            failed += 1
        except httpx.ConnectError:
            print(f"  [FAIL] Could not connect to API at {API_URL}")
            print("  Make sure the API is running: docker compose up")
            failed += 1
            break
        except Exception as e:
            print(f"  [FAIL] Unexpected error: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
