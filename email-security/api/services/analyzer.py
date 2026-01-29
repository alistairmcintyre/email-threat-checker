import re
import time
import json
import httpx
from urllib.parse import urlparse

from config import settings
from models import (
    EmailRequest,
    AnalysisResponse,
    Verdict,
    ThreatIndicator,
    ThreatType,
    SimilarThreat,
)
from services.embeddings import EmbeddingService
from services.rag import RAGService


class AnalyzerService:
    def __init__(
        self,
        embedding_service: EmbeddingService,
        rag_service: RAGService,
    ):
        self.embedding_service = embedding_service
        self.rag_service = rag_service
        self.ollama_host = settings.ollama_host
        self.llm_model = settings.llm_model

    async def analyze_email(self, email: EmailRequest) -> AnalysisResponse:
        """Perform full threat analysis on an email."""
        start_time = time.time()

        # Run heuristic checks
        heuristic_threats = await self._run_heuristic_checks(email)

        # Generate embedding for email content
        email_text = self._email_to_text(email)
        embedding = await self.embedding_service.get_embedding(email_text)

        # Search for similar threats (high threshold to reduce false positives)
        similar_threats = await self.rag_service.search_similar_threats(
            embedding, limit=5, score_threshold=0.65
        )

        # Get RAG context
        rag_context = await self.rag_service.get_threat_context(embedding, limit=3)

        # Run LLM analysis
        llm_result = await self._llm_analyze(email, rag_context, heuristic_threats)

        # Combine results
        all_threats = heuristic_threats + llm_result.get("threats", [])
        confidence = self._calculate_confidence(all_threats, similar_threats)
        verdict = self._determine_verdict(confidence, all_threats)

        processing_time = (time.time() - start_time) * 1000

        return AnalysisResponse(
            verdict=verdict,
            confidence=confidence,
            threats_detected=all_threats,
            similar_threats=similar_threats,
            explanation=llm_result.get("explanation", "Analysis complete."),
            processing_time_ms=processing_time,
        )

    def _email_to_text(self, email: EmailRequest) -> str:
        """Convert email to searchable text."""
        parts = [
            f"From: {email.sender}",
            f"To: {', '.join(email.to)}",
            f"Subject: {email.subject}",
            f"Body: {email.body}",
        ]
        if email.attachments:
            attachment_names = [a.filename for a in email.attachments]
            parts.append(f"Attachments: {', '.join(attachment_names)}")
        return "\n".join(parts)

    async def _run_heuristic_checks(
        self, email: EmailRequest
    ) -> list[ThreatIndicator]:
        """Run rule-based threat detection."""
        threats = []

        # Check for suspicious sender patterns
        sender_threats = self._check_sender(email.sender)
        threats.extend(sender_threats)

        # Check subject for urgency/phishing keywords
        subject_threats = self._check_subject(email.subject)
        threats.extend(subject_threats)

        # Check body for suspicious URLs and content
        body_threats = self._check_body(email.body)
        threats.extend(body_threats)

        # Check attachments for dangerous types
        attachment_threats = self._check_attachments(email.attachments)
        threats.extend(attachment_threats)

        # Check headers for spoofing
        header_threats = self._check_headers(email.headers)
        threats.extend(header_threats)

        return threats

    def _check_sender(self, sender: str) -> list[ThreatIndicator]:
        """Check sender for suspicious patterns."""
        threats = []

        # Check for lookalike domains
        lookalike_patterns = [
            r"paypa[l1]", r"amaz[o0]n", r"g[o0]{2}gle", r"micr[o0]s[o0]ft",
            r"app[l1]e", r"faceb[o0]{2}k", r"netf[l1]ix",
        ]
        sender_lower = sender.lower()
        for pattern in lookalike_patterns:
            if re.search(pattern, sender_lower) and not re.search(
                r"@(paypal|amazon|google|microsoft|apple|facebook|netflix)\.", sender_lower
            ):
                threats.append(
                    ThreatIndicator(
                        threat_type=ThreatType.SPOOFING,
                        indicator=f"Lookalike domain detected: {sender}",
                        confidence=0.8,
                        details="Sender domain mimics a known brand",
                    )
                )
                break

        # Check for suspicious TLDs
        suspicious_tlds = [".xyz", ".top", ".click", ".loan", ".work", ".gq", ".ml", ".tk"]
        for tld in suspicious_tlds:
            if sender_lower.endswith(tld):
                threats.append(
                    ThreatIndicator(
                        threat_type=ThreatType.PHISHING,
                        indicator=f"Suspicious TLD: {tld}",
                        confidence=0.5,
                        details="Email sent from high-risk top-level domain",
                    )
                )
                break

        return threats

    def _check_subject(self, subject: str) -> list[ThreatIndicator]:
        """Check subject line for phishing indicators."""
        threats = []
        subject_lower = subject.lower()

        urgency_keywords = [
            "urgent", "immediate", "action required", "suspended",
            "verify", "confirm", "update required", "expire",
            "locked", "unauthorized", "security alert",
        ]

        for keyword in urgency_keywords:
            if keyword in subject_lower:
                threats.append(
                    ThreatIndicator(
                        threat_type=ThreatType.PHISHING,
                        indicator=f"Urgency keyword in subject: '{keyword}'",
                        confidence=0.6,
                        details="Subject uses urgency tactics common in phishing",
                    )
                )
                break

        return threats

    def _check_body(self, body: str) -> list[ThreatIndicator]:
        """Check email body for suspicious content."""
        threats = []

        # Extract and check URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, body)

        for url in urls:
            parsed = urlparse(url)

            # Check for IP addresses instead of domains
            if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
                threats.append(
                    ThreatIndicator(
                        threat_type=ThreatType.PHISHING,
                        indicator=f"URL with IP address: {url[:50]}...",
                        confidence=0.7,
                        details="URLs using IP addresses are often malicious",
                    )
                )

            # Check for URL shorteners
            shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
            if any(s in parsed.netloc.lower() for s in shorteners):
                threats.append(
                    ThreatIndicator(
                        threat_type=ThreatType.PHISHING,
                        indicator=f"URL shortener detected: {parsed.netloc}",
                        confidence=0.5,
                        details="URL shorteners can hide malicious destinations",
                    )
                )

        # Check for credential harvesting language
        credential_patterns = [
            r"enter your (password|credentials|login)",
            r"verify your (account|identity)",
            r"click (here|below) to (verify|confirm|update)",
            r"your account (has been|will be) (suspended|locked|terminated)",
        ]

        body_lower = body.lower()
        for pattern in credential_patterns:
            if re.search(pattern, body_lower):
                threats.append(
                    ThreatIndicator(
                        threat_type=ThreatType.PHISHING,
                        indicator="Credential harvesting language detected",
                        confidence=0.7,
                        details=f"Pattern matched: {pattern}",
                    )
                )
                break

        return threats

    def _check_attachments(self, attachments: list) -> list[ThreatIndicator]:
        """Check attachments for dangerous file types."""
        threats = []

        dangerous_extensions = [
            ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
            ".vbs", ".js", ".jar", ".msi", ".ps1", ".hta",
        ]

        double_extension_pattern = r'\.[a-z]{2,4}\.(exe|scr|bat|cmd|js|vbs)$'

        for attachment in attachments:
            filename_lower = attachment.filename.lower()

            # Check for dangerous extensions
            for ext in dangerous_extensions:
                if filename_lower.endswith(ext):
                    threats.append(
                        ThreatIndicator(
                            threat_type=ThreatType.MALWARE,
                            indicator=f"Dangerous attachment: {attachment.filename}",
                            confidence=0.9,
                            details=f"File has executable extension: {ext}",
                        )
                    )
                    break

            # Check for double extensions (e.g., document.pdf.exe)
            if re.search(double_extension_pattern, filename_lower):
                threats.append(
                    ThreatIndicator(
                        threat_type=ThreatType.MALWARE,
                        indicator=f"Double extension: {attachment.filename}",
                        confidence=0.95,
                        details="Double extension is a common malware obfuscation technique",
                    )
                )

        return threats

    def _check_headers(self, headers: dict) -> list[ThreatIndicator]:
        """Check email headers for spoofing indicators."""
        threats = []

        # Check for SPF/DKIM/DMARC failures if present
        auth_results = headers.get("Authentication-Results", "").lower()
        if auth_results:
            if "spf=fail" in auth_results:
                threats.append(
                    ThreatIndicator(
                        threat_type=ThreatType.SPOOFING,
                        indicator="SPF authentication failed",
                        confidence=0.8,
                        details="Sender's domain SPF record doesn't authorize this server",
                    )
                )
            if "dkim=fail" in auth_results:
                threats.append(
                    ThreatIndicator(
                        threat_type=ThreatType.SPOOFING,
                        indicator="DKIM signature failed",
                        confidence=0.8,
                        details="Email's DKIM signature is invalid",
                    )
                )
            if "dmarc=fail" in auth_results:
                threats.append(
                    ThreatIndicator(
                        threat_type=ThreatType.SPOOFING,
                        indicator="DMARC policy failed",
                        confidence=0.85,
                        details="Email fails sender's DMARC policy",
                    )
                )

        return threats

    async def _llm_analyze(
        self,
        email: EmailRequest,
        rag_context: str,
        heuristic_threats: list[ThreatIndicator],
    ) -> dict:
        """Use LLM to analyze email with RAG context."""

        heuristic_summary = ""
        if heuristic_threats:
            heuristic_summary = "\n".join(
                f"- {t.threat_type.value}: {t.indicator}" for t in heuristic_threats
            )

        prompt = f"""You are an email security analyst. Analyze this email for potential threats.

EMAIL CONTENT:
From: {email.sender}
To: {', '.join(email.to)}
Subject: {email.subject}
Body:
{email.body[:2000]}

Attachments: {', '.join(a.filename for a in email.attachments) or 'None'}

{rag_context}

HEURISTIC DETECTIONS:
{heuristic_summary or 'None'}

Analyze this email and provide:
1. Your assessment of the threat level
2. Any additional threats not caught by heuristics
3. A brief explanation of your reasoning

Respond in JSON format:
{{
    "additional_threats": [
        {{"type": "phishing|malware|bec|spam|spoofing|social_engineering", "indicator": "description", "confidence": 0.0-1.0}}
    ],
    "explanation": "Your analysis explanation"
}}"""

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.ollama_host}/api/generate",
                    json={
                        "model": self.llm_model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                    },
                )
                response.raise_for_status()
                data = response.json()
                result = json.loads(data["response"])

                # Convert additional threats to ThreatIndicator objects
                additional_threats = []
                for t in result.get("additional_threats", []):
                    try:
                        additional_threats.append(
                            ThreatIndicator(
                                threat_type=ThreatType(t["type"]),
                                indicator=t["indicator"],
                                confidence=float(t.get("confidence", 0.5)),
                            )
                        )
                    except (ValueError, KeyError):
                        continue

                return {
                    "threats": additional_threats,
                    "explanation": result.get("explanation", "Analysis complete."),
                }
        except Exception as e:
            return {
                "threats": [],
                "explanation": f"LLM analysis unavailable: {str(e)}",
            }

    def _calculate_confidence(
        self,
        threats: list[ThreatIndicator],
        similar_threats: list[SimilarThreat],
    ) -> float:
        """Calculate overall threat confidence score."""
        # No threats detected = safe
        if not threats:
            return 0.0

        # Base confidence from detected threats
        threat_score = max(t.confidence for t in threats)

        # Similar threats only BOOST confidence when threats ARE detected
        # They should not trigger suspicion on their own
        if similar_threats:
            max_similarity = max(t.similarity_score for t in similar_threats)
            # Only boost if similarity is high (>0.7) and we have threats
            if max_similarity > 0.7:
                threat_score = min(threat_score * 1.1, 1.0)

        # Boost if multiple indicators
        if len(threats) >= 3:
            threat_score = min(threat_score * 1.2, 1.0)

        return round(threat_score, 2)

    def _determine_verdict(
        self,
        confidence: float,
        threats: list[ThreatIndicator],
    ) -> Verdict:
        """Determine final verdict based on confidence and threats."""
        # Immediate quarantine for high-confidence malware
        malware_threats = [t for t in threats if t.threat_type == ThreatType.MALWARE]
        if malware_threats and any(t.confidence >= 0.8 for t in malware_threats):
            return Verdict.QUARANTINE

        if confidence >= settings.quarantine_threshold:
            return Verdict.QUARANTINE
        elif confidence >= settings.suspicious_threshold:
            return Verdict.SUSPICIOUS
        else:
            return Verdict.SAFE
