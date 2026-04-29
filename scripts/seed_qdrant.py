#!/usr/bin/env python3
"""
Seed script for populating Qdrant with threat patterns.

This script reads threat patterns from JSON files and creates embeddings
using Ollama's nomic-embed-text model, then stores them in Qdrant.
"""

import hashlib
import json
import os
import sys
import time
import httpx
from pathlib import Path

from qdrant_client import QdrantClient, models
from qdrant_client.http.exceptions import UnexpectedResponse


# Configuration from environment
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
QDRANT_HOST = os.environ.get("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.environ.get("QDRANT_PORT", "6333"))
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "nomic-embed-text")
COLLECTION_NAME = os.environ.get("QDRANT_COLLECTION", "email_threats")
VECTOR_SIZE = 768  # nomic-embed-text dimension

DATA_DIR = Path("/app/data/seed")


def wait_for_ollama(max_retries: int = 30, delay: int = 2) -> bool:
    """Wait for Ollama to be ready."""
    print(f"Waiting for Ollama at {OLLAMA_HOST}...")
    for i in range(max_retries):
        try:
            response = httpx.get(f"{OLLAMA_HOST}/api/tags", timeout=5.0)
            if response.status_code == 200:
                print("Ollama is ready!")
                return True
        except Exception:
            pass
        print(f"  Attempt {i + 1}/{max_retries}...")
        time.sleep(delay)
    return False


def wait_for_embedding_model(max_retries: int = 60, delay: int = 5) -> bool:
    """Wait for embedding model to be available."""
    print(f"Waiting for embedding model {EMBEDDING_MODEL}...")
    for i in range(max_retries):
        try:
            response = httpx.get(f"{OLLAMA_HOST}/api/tags", timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                models_list = [m["name"] for m in data.get("models", [])]
                if EMBEDDING_MODEL in models_list or f"{EMBEDDING_MODEL}:latest" in models_list:
                    print(f"Embedding model {EMBEDDING_MODEL} is ready!")
                    return True
        except Exception:
            pass
        print(f"  Attempt {i + 1}/{max_retries} - model not yet available...")
        time.sleep(delay)
    return False


def get_embedding(text: str) -> list[float]:
    """Generate embedding for text using Ollama."""
    response = httpx.post(
        f"{OLLAMA_HOST}/api/embed",
        json={"model": EMBEDDING_MODEL, "input": text},
        timeout=60.0,
    )
    response.raise_for_status()
    return response.json()["embeddings"][0]


def create_collection(client: QdrantClient) -> None:
    """Create or recreate the collection."""
    try:
        existing = client.get_collection(COLLECTION_NAME)
        print(f"Collection {COLLECTION_NAME} exists with {existing.points_count} points")
        if existing.points_count > 0:
            print("Collection already seeded, skipping...")
            return None
    except (UnexpectedResponse, Exception):
        print(f"Creating collection {COLLECTION_NAME}...")
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=models.VectorParams(
                size=VECTOR_SIZE,
                distance=models.Distance.COSINE,
            ),
        )
    return True


def load_patterns(filepath: Path) -> list[dict]:
    """Load threat patterns from JSON file."""
    if not filepath.exists():
        print(f"Warning: {filepath} not found")
        return []
    with open(filepath) as f:
        return json.load(f)


def seed_patterns(client: QdrantClient, patterns: list[dict]) -> int:
    """Seed patterns into Qdrant."""
    points = []
    for pattern in patterns:
        # Create text for embedding
        text = f"{pattern['pattern']} {pattern['description']} {' '.join(pattern.get('examples', []))}"

        print(f"  Generating embedding for: {pattern['id']}")
        embedding = get_embedding(text)

        points.append(
            models.PointStruct(
                id=int(hashlib.sha1(pattern["id"].encode()).hexdigest()[:16], 16),
                vector=embedding,
                payload={
                    "id": pattern["id"],
                    "threat_type": pattern["threat_type"],
                    "pattern": pattern["pattern"],
                    "description": pattern["description"],
                    "severity": pattern["severity"],
                    "indicators": pattern.get("indicators", []),
                    "examples": pattern.get("examples", []),
                },
            )
        )

    if points:
        client.upsert(collection_name=COLLECTION_NAME, points=points)

    return len(points)


def main():
    print("=" * 60)
    print("Email Security - Qdrant Seeder")
    print("=" * 60)

    # Wait for dependencies
    if not wait_for_ollama():
        print("ERROR: Ollama is not available")
        sys.exit(1)

    if not wait_for_embedding_model():
        print(f"ERROR: Embedding model {EMBEDDING_MODEL} is not available")
        print("Make sure to run: ollama pull nomic-embed-text")
        sys.exit(1)

    # Connect to Qdrant
    print(f"\nConnecting to Qdrant at {QDRANT_HOST}:{QDRANT_PORT}...")
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

    # Create collection
    should_seed = create_collection(client)
    if should_seed is None:
        print("\nSeeding complete (skipped - already populated)")
        return

    # Load and seed patterns
    total_seeded = 0

    print("\nLoading phishing patterns...")
    phishing = load_patterns(DATA_DIR / "phishing_patterns.json")
    if phishing:
        count = seed_patterns(client, phishing)
        total_seeded += count
        print(f"  Seeded {count} phishing patterns")

    print("\nLoading suspicious domains...")
    domains = load_patterns(DATA_DIR / "suspicious_domains.json")
    if domains:
        count = seed_patterns(client, domains)
        total_seeded += count
        print(f"  Seeded {count} domain patterns")

    print("\nLoading social engineering patterns...")
    social = load_patterns(DATA_DIR / "social_engineering.json")
    if social:
        count = seed_patterns(client, social)
        total_seeded += count
        print(f"  Seeded {count} social engineering patterns")

    print("\n" + "=" * 60)
    print(f"Seeding complete! Total patterns: {total_seeded}")
    print("=" * 60)


if __name__ == "__main__":
    main()
