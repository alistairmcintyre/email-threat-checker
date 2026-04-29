import hashlib

from qdrant_client import QdrantClient, models
from qdrant_client.http.exceptions import UnexpectedResponse

from config import settings
from models import ThreatPattern, ThreatType, SimilarThreat


def _stable_point_id(pattern_id: str) -> int:
    return int(hashlib.sha1(pattern_id.encode()).hexdigest()[:16], 16)


class RAGService:
    def __init__(self):
        self.client = QdrantClient(
            host=settings.qdrant_host,
            port=settings.qdrant_port,
        )
        self.collection_name = settings.qdrant_collection
        self.vector_size = 768  # nomic-embed-text dimension

    async def ensure_collection(self) -> None:
        """Create collection if it doesn't exist."""
        try:
            self.client.get_collection(self.collection_name)
        except (UnexpectedResponse, Exception):
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=models.VectorParams(
                    size=self.vector_size,
                    distance=models.Distance.COSINE,
                ),
            )

    async def add_threat_pattern(
        self,
        pattern: ThreatPattern,
        embedding: list[float],
    ) -> None:
        """Add a threat pattern to the vector database."""
        self.client.upsert(
            collection_name=self.collection_name,
            points=[
                models.PointStruct(
                    id=_stable_point_id(pattern.id),
                    vector=embedding,
                    payload={
                        "id": pattern.id,
                        "threat_type": pattern.threat_type.value,
                        "pattern": pattern.pattern,
                        "description": pattern.description,
                        "severity": pattern.severity,
                        "indicators": pattern.indicators,
                        "examples": pattern.examples,
                    },
                )
            ],
        )

    async def search_similar_threats(
        self,
        query_embedding: list[float],
        limit: int = 5,
        score_threshold: float = 0.5,
    ) -> list[SimilarThreat]:
        """Search for similar threats based on embedding."""
        results = self.client.query_points(
            collection_name=self.collection_name,
            query=query_embedding,
            limit=limit,
            score_threshold=score_threshold,
        )

        similar_threats = []
        for result in results.points:
            payload = result.payload
            similar_threats.append(
                SimilarThreat(
                    threat_id=payload["id"],
                    similarity_score=result.score,
                    description=payload["description"],
                    threat_type=ThreatType(payload["threat_type"]),
                )
            )
        return similar_threats

    async def get_threat_context(
        self,
        query_embedding: list[float],
        limit: int = 3,
    ) -> str:
        """Get threat context for RAG prompt augmentation."""
        results = self.client.query_points(
            collection_name=self.collection_name,
            query=query_embedding,
            limit=limit,
        )

        if not results.points:
            return "No similar threats found in database."

        context_parts = ["Similar known threats:"]
        for i, result in enumerate(results.points, 1):
            payload = result.payload
            context_parts.append(
                f"{i}. [{payload['threat_type']}] {payload['description']}\n"
                f"   Pattern: {payload['pattern']}\n"
                f"   Indicators: {', '.join(payload['indicators'][:3])}"
            )
        return "\n".join(context_parts)

    async def health_check(self) -> bool:
        """Check if Qdrant is available."""
        try:
            self.client.get_collections()
            return True
        except Exception:
            return False

    async def get_collection_count(self) -> int:
        """Get number of vectors in collection."""
        try:
            info = self.client.get_collection(self.collection_name)
            return info.points_count
        except Exception:
            return 0
