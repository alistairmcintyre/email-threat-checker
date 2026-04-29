"""Hermetic unit tests for AnalyzerService.

These tests instantiate AnalyzerService directly with mocked Embedding and
RAG dependencies, and patch httpx.AsyncClient inside services.analyzer so
no Ollama, Qdrant, or Docker is required. They run on every commit.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models import EmailRequest, Verdict
from services import analyzer as analyzer_module
from services.analyzer import AnalyzerService


def make_email(**overrides) -> EmailRequest:
    defaults = dict(
        sender="colleague@company.com",
        to=["you@company.com"],
        subject="Meeting notes",
        body="Here are today's meeting notes.",
        attachments=[],
        headers={"Authentication-Results": "spf=pass; dkim=pass; dmarc=pass"},
    )
    defaults.update(overrides)
    return EmailRequest(**defaults)


def make_httpx_patch(llm_response: dict):
    """Patch httpx.AsyncClient inside services.analyzer with a canned LLM reply."""
    response_mock = MagicMock()
    response_mock.raise_for_status = MagicMock()
    response_mock.json = MagicMock(return_value={"response": json.dumps(llm_response)})

    client_mock = MagicMock()
    client_mock.__aenter__ = AsyncMock(return_value=client_mock)
    client_mock.__aexit__ = AsyncMock(return_value=None)
    client_mock.post = AsyncMock(return_value=response_mock)

    return patch.object(analyzer_module.httpx, "AsyncClient", return_value=client_mock), client_mock


@pytest.fixture
def fake_embeddings():
    svc = MagicMock()
    svc.get_embedding = AsyncMock(return_value=[0.0] * 768)
    return svc


@pytest.fixture
def fake_rag():
    svc = MagicMock()
    svc.search_similar_threats = AsyncMock(return_value=[])
    svc.get_threat_context = AsyncMock(return_value="No similar threats found in database.")
    return svc


def test_safe_email_returns_zero_confidence(fake_embeddings, fake_rag):
    patcher, _ = make_httpx_patch({"additional_threats": [], "explanation": "Looks clean."})
    with patcher:
        analyzer = AnalyzerService(fake_embeddings, fake_rag)
        result = asyncio.run(analyzer.analyze_email(make_email()))

    assert result.verdict == Verdict.SAFE
    assert result.confidence == 0.0
    assert result.threats_detected == []


def test_phishing_email_is_quarantined(fake_embeddings, fake_rag):
    patcher, _ = make_httpx_patch(
        {
            "additional_threats": [
                {"type": "phishing", "indicator": "Credential harvesting", "confidence": 0.85}
            ],
            "explanation": "Phishing email targeting PayPal users.",
        }
    )
    with patcher:
        analyzer = AnalyzerService(fake_embeddings, fake_rag)
        result = asyncio.run(
            analyzer.analyze_email(
                make_email(
                    sender="security@paypa1-verify.xyz",
                    subject="URGENT: Verify your account immediately",
                    body="Click here to verify your account: http://192.168.1.100/paypal/verify",
                    headers={"Authentication-Results": "spf=fail; dkim=fail"},
                )
            )
        )

    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.QUARANTINE)
    assert result.confidence >= 0.5
    assert any(t.threat_type.value == "phishing" for t in result.threats_detected)


def test_analyzer_passes_deterministic_options_to_ollama(fake_embeddings, fake_rag):
    """Regression guard: analyzer must request temperature=0 + fixed seed."""
    patcher, client_mock = make_httpx_patch({"additional_threats": [], "explanation": "ok"})
    with patcher:
        analyzer = AnalyzerService(fake_embeddings, fake_rag)
        asyncio.run(analyzer.analyze_email(make_email()))

    client_mock.post.assert_called_once()
    payload = client_mock.post.call_args.kwargs["json"]
    assert payload["options"]["temperature"] == 0.0
    assert payload["options"]["seed"] == 42


def test_analyze_email_is_deterministic_across_calls(fake_embeddings, fake_rag):
    """Two consecutive analyses on identical input must produce identical output
    (apart from processing_time_ms)."""
    patcher, _ = make_httpx_patch(
        {
            "additional_threats": [
                {"type": "phishing", "indicator": "Credential harvesting", "confidence": 0.85}
            ],
            "explanation": "Phishing email.",
        }
    )
    email = make_email(
        sender="security@paypa1-verify.xyz",
        subject="URGENT: Verify your account",
        body="Click here to verify: http://192.168.1.100/login",
        headers={"Authentication-Results": "spf=fail; dkim=fail"},
    )
    with patcher:
        analyzer = AnalyzerService(fake_embeddings, fake_rag)
        r1 = asyncio.run(analyzer.analyze_email(email))
        r2 = asyncio.run(analyzer.analyze_email(email))

    assert r1.verdict == r2.verdict
    assert r1.confidence == r2.confidence
    assert r1.explanation == r2.explanation
    assert [t.model_dump() for t in r1.threats_detected] == [
        t.model_dump() for t in r2.threats_detected
    ]
    assert [t.model_dump() for t in r1.similar_threats] == [
        t.model_dump() for t in r2.similar_threats
    ]


def test_llm_failure_does_not_break_analysis(fake_embeddings, fake_rag):
    """If Ollama is unreachable, analyzer still returns a deterministic verdict
    based on heuristics alone."""
    with patch.object(
        analyzer_module.httpx,
        "AsyncClient",
        side_effect=RuntimeError("Ollama down"),
    ):
        analyzer = AnalyzerService(fake_embeddings, fake_rag)
        result = asyncio.run(
            analyzer.analyze_email(
                make_email(
                    sender="security@paypa1-verify.xyz",
                    subject="URGENT: Verify your account",
                    body="Click here to verify: http://192.168.1.100/login",
                    headers={"Authentication-Results": "spf=fail; dkim=fail"},
                )
            )
        )

    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.QUARANTINE)
    assert "LLM analysis unavailable" in result.explanation
