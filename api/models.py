from enum import Enum
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    QUARANTINE = "quarantine"


class ThreatType(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    BEC = "business_email_compromise"
    SPAM = "spam"
    SPOOFING = "spoofing"
    SOCIAL_ENGINEERING = "social_engineering"


class Attachment(BaseModel):
    filename: str
    content_type: str | None = None
    size: int | None = None
    content_base64: str | None = Field(default=None, description="Base64 encoded content")


class EmailRequest(BaseModel):
    sender: str = Field(..., alias="from", description="Sender email address")
    to: list[str] = Field(default_factory=list, description="Recipient email addresses")
    cc: list[str] = Field(default_factory=list, description="CC recipients")
    bcc: list[str] = Field(default_factory=list, description="BCC recipients")
    subject: str = Field(default="", description="Email subject line")
    body: str = Field(default="", description="Email body content")
    body_html: str | None = Field(default=None, description="HTML body if available")
    headers: dict[str, str] = Field(default_factory=dict, description="Email headers")
    attachments: list[Attachment] = Field(default_factory=list, description="Email attachments")

    class Config:
        populate_by_name = True


class ThreatIndicator(BaseModel):
    threat_type: ThreatType
    indicator: str
    confidence: float = Field(ge=0.0, le=1.0)
    details: str | None = None


class SimilarThreat(BaseModel):
    threat_id: str
    similarity_score: float = Field(ge=0.0, le=1.0)
    description: str
    threat_type: ThreatType


class AnalysisResponse(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    threats_detected: list[ThreatIndicator] = Field(default_factory=list)
    similar_threats: list[SimilarThreat] = Field(default_factory=list)
    explanation: str
    processing_time_ms: float | None = None


class ThreatPattern(BaseModel):
    id: str
    threat_type: ThreatType
    pattern: str
    description: str
    severity: float = Field(ge=0.0, le=1.0, description="Severity score 0-1")
    indicators: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    ollama_connected: bool
    qdrant_connected: bool
    models_loaded: list[str]
