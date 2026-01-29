# Email Security RAG System

Local, open-source email threat detection system using RAG (Retrieval Augmented Generation) with Ollama and Qdrant.

## Architecture

```
┌─────────────┬─────────────┬─────────────┐
│   Ollama    │   Qdrant    │  FastAPI    │
│  (LLM +     │  (Vector    │  (Email     │
│  Embeddings)│   Store)    │   API)      │
└─────────────┴─────────────┴─────────────┘
```

- **Ollama** - Local LLM (llama3.2:3b) + embeddings (nomic-embed-text)
- **Qdrant** - Vector database for threat pattern storage
- **FastAPI** - REST API for email analysis

## Prerequisites

- Docker and Docker Compose
- ~4GB disk space for models
- 8GB+ RAM recommended

## Quick Start

### 1. Start Services

```bash
cd email-security
docker-compose up -d
```

First run will download models (~2GB). Monitor progress:

```bash
docker-compose logs -f ollama-pull
```

### 2. Check Health

Wait for all services to be healthy:

```bash
docker-compose ps
```

Or check the API:

```bash
curl http://localhost:8000/health
```

Expected response when ready:
```json
{
  "status": "healthy",
  "ollama_connected": true,
  "qdrant_connected": true,
  "models_loaded": ["nomic-embed-text", "llama3.2:3b"]
}
```

### 3. Seed Threat Database (First Run)

```bash
docker-compose run --rm seed
```

Verify patterns loaded:

```bash
curl http://localhost:8000/api/v1/stats
```

## Testing

### Test a Safe Email

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "from": "colleague@company.com",
    "to": ["you@company.com"],
    "subject": "Meeting notes from today",
    "body": "Hi,\n\nHere are the notes from our meeting.\n\nBest,\nJohn",
    "headers": {"Authentication-Results": "spf=pass; dkim=pass"},
    "attachments": []
  }'
```

Expected: `"verdict": "safe"`

### Test a Phishing Email

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "from": "security@paypa1-verify.xyz",
    "to": ["victim@company.com"],
    "subject": "URGENT: Your account has been suspended - Verify immediately",
    "body": "Dear Valued Customer,\n\nWe have detected unusual activity on your PayPal account.\n\nVerify your identity immediately:\nhttp://192.168.1.100/paypal/verify?user=victim@company.com\n\nPayPal Security Team",
    "headers": {"Authentication-Results": "spf=fail; dkim=fail", "Reply-To": "scammer@gmail.com"},
    "attachments": []
  }'
```

Expected: `"verdict": "quarantine"` with threats like:
- Lookalike domain (paypa1)
- Suspicious TLD (.xyz)
- Urgency keywords
- IP address in URL
- SPF/DKIM failure

### Test a Malware Email

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "from": "invoices@supplier.com",
    "to": ["accounts@company.com"],
    "subject": "Invoice #12345",
    "body": "Please find attached invoice for payment.",
    "headers": {},
    "attachments": [{"filename": "Invoice.pdf.exe", "content_type": "application/octet-stream"}]
  }'
```

Expected: `"verdict": "quarantine"` with malware indicator for double extension

### Test a BEC (Business Email Compromise)

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "from": "ceo@company-corp.com",
    "to": ["finance@company.com"],
    "subject": "Urgent - Wire Transfer Needed",
    "body": "I need you to process an urgent wire transfer of $45,000.\n\nThis is confidential. Do not discuss with anyone.\n\nThanks,\nCEO",
    "headers": {"Reply-To": "ceo.smith@gmail.com"},
    "attachments": []
  }'
```

Expected: `"verdict": "suspicious"` or `"quarantine"`

### Run Integration Tests

```bash
python tests/test_api.py
```

## API Reference

### POST /api/v1/analyze

Analyze an email for threats.

**Request:**
```json
{
  "from": "sender@example.com",
  "to": ["recipient@example.com"],
  "cc": [],
  "bcc": [],
  "subject": "Email subject",
  "body": "Email body text",
  "body_html": "<html>...</html>",
  "headers": {
    "Authentication-Results": "spf=pass; dkim=pass",
    "Reply-To": "reply@example.com"
  },
  "attachments": [
    {
      "filename": "document.pdf",
      "content_type": "application/pdf",
      "size": 12345
    }
  ]
}
```

**Response:**
```json
{
  "verdict": "safe|suspicious|quarantine",
  "confidence": 0.92,
  "threats_detected": [
    {
      "threat_type": "phishing|malware|spoofing|bec|spam|social_engineering",
      "indicator": "Description of the threat",
      "confidence": 0.8,
      "details": "Additional details"
    }
  ],
  "similar_threats": [
    {
      "threat_id": "phish-001",
      "similarity_score": 0.85,
      "description": "Known threat description",
      "threat_type": "phishing"
    }
  ],
  "explanation": "Analysis summary",
  "processing_time_ms": 1234.56
}
```

### GET /health

Check service health.

### GET /api/v1/stats

Get threat database statistics.

## Threat Detection

The system detects:

| Threat Type | Indicators |
|-------------|------------|
| **Phishing** | Urgency keywords, credential harvesting, suspicious URLs, URL shorteners |
| **Spoofing** | Typosquatting domains, SPF/DKIM/DMARC failures, Reply-To mismatch |
| **Malware** | Dangerous file extensions (.exe, .scr), double extensions |
| **BEC** | Executive impersonation, wire transfer requests, confidentiality pressure |
| **Social Engineering** | Authority tactics, fear/urgency, reward bait |

## Configuration

Environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `http://ollama:11434` | Ollama server URL |
| `LLM_MODEL` | `llama3.2:3b` | LLM model for analysis |
| `EMBEDDING_MODEL` | `nomic-embed-text` | Embedding model |
| `QDRANT_HOST` | `qdrant` | Qdrant server host |
| `QUARANTINE_THRESHOLD` | `0.8` | Confidence threshold for quarantine |
| `SUSPICIOUS_THRESHOLD` | `0.5` | Confidence threshold for suspicious |

## Stopping

```bash
docker-compose down
```

To remove all data (models, vectors):

```bash
docker-compose down -v
```

## Troubleshooting

### Models not loading

Check ollama-pull logs:
```bash
docker-compose logs ollama-pull
```

Pull manually:
```bash
docker exec -it email-security-ollama ollama pull llama3.2:3b
docker exec -it email-security-ollama ollama pull nomic-embed-text
```

### API unhealthy

Check API logs:
```bash
docker-compose logs api
```

### Slow analysis

First request loads the model into memory (~30-60s). Subsequent requests are faster.
