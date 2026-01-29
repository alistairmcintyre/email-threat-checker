import httpx
from config import settings


class EmbeddingService:
    def __init__(self):
        self.base_url = settings.ollama_host
        self.model = settings.embedding_model

    async def get_embedding(self, text: str) -> list[float]:
        """Generate embedding for a single text using Ollama."""
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.base_url}/api/embed",
                json={
                    "model": self.model,
                    "input": text,
                },
            )
            response.raise_for_status()
            data = response.json()
            return data["embeddings"][0]

    async def get_embeddings(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for multiple texts."""
        embeddings = []
        for text in texts:
            embedding = await self.get_embedding(text)
            embeddings.append(embedding)
        return embeddings

    async def health_check(self) -> bool:
        """Check if Ollama is available and the embedding model is loaded."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                response.raise_for_status()
                data = response.json()
                models = [m["name"] for m in data.get("models", [])]
                return self.model in models or f"{self.model}:latest" in models
        except Exception:
            return False
