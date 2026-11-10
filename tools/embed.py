"""One embedding model for indexing and querying: BAAI/bge-small-en-v1.5 via fastembed (ONNX, CPU).

bge models expect queries and passages to be embedded differently (queries get an instruction
prefix). fastembed's `query_embed` / `passage_embed` handle that, so we always use the pair.
"""

from functools import lru_cache
from pathlib import Path

from fastembed import TextEmbedding

MODEL = "BAAI/bge-small-en-v1.5"
CACHE = Path(__file__).parent.parent / ".cache" / "fastembed"


@lru_cache(maxsize=1)
def model() -> TextEmbedding:
    return TextEmbedding(MODEL, cache_dir=str(CACHE))


def embed_passages(texts: list[str]) -> list[list[float]]:
    return [v.tolist() for v in model().passage_embed(texts, batch_size=64)]


def embed_query(text: str) -> list[float]:
    return next(iter(model().query_embed(text))).tolist()
