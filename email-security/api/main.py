"""
Email Security API

A local, open-source email threat detection system using RAG + MCP architecture.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from models import EmailRequest, AnalysisResponse, HealthResponse
from services.embeddings import EmbeddingService
from services.rag import RAGService
from services.analyzer import AnalyzerService


# Service instances
embedding_service = EmbeddingService()
rag_service = RAGService()
analyzer_service = AnalyzerService(embedding_service, rag_service)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    await rag_service.ensure_collection()
    yield
    # Shutdown (nothing to clean up)


app = FastAPI(
    title="Email Security API",
    description="Local email threat detection using RAG and LLM analysis",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Check health of all services."""
    ollama_ok = await embedding_service.health_check()
    qdrant_ok = await rag_service.health_check()

    models_loaded = []
    if ollama_ok:
        models_loaded.append(settings.embedding_model)
        models_loaded.append(settings.llm_model)

    status = "healthy" if (ollama_ok and qdrant_ok) else "degraded"

    return HealthResponse(
        status=status,
        ollama_connected=ollama_ok,
        qdrant_connected=qdrant_ok,
        models_loaded=models_loaded,
    )


@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_email(email: EmailRequest):
    """
    Analyze an email for potential security threats.

    This endpoint performs:
    1. Heuristic rule-based checks (sender, URLs, attachments, headers)
    2. RAG retrieval of similar known threats
    3. LLM-powered threat analysis with context

    Returns a verdict (safe/suspicious/quarantine) with detailed threat indicators.
    """
    try:
        result = await analyzer_service.analyze_email(email)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}",
        )


@app.get("/api/v1/stats")
async def get_stats():
    """Get statistics about the threat database."""
    threat_count = await rag_service.get_collection_count()
    return {
        "threat_patterns_loaded": threat_count,
        "collection_name": settings.qdrant_collection,
        "llm_model": settings.llm_model,
        "embedding_model": settings.embedding_model,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
    )
