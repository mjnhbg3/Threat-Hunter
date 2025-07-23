import json
import os
import hashlib
from typing import List, Dict, Any

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

from threat_hunter.utils.logger import logger


class VectorDB:
    """Simple FAISS based vector database with metadata persistence."""

    def __init__(self, db_dir: str):
        self.db_dir = db_dir
        os.makedirs(db_dir, exist_ok=True)
        self.index_path = os.path.join(db_dir, "vectors.faiss")
        self.meta_path = os.path.join(db_dir, "metadata.json")
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.index = faiss.IndexFlatL2(self.model.get_sentence_embedding_dimension())
        self.index = faiss.IndexIDMap(self.index)
        self.metadata: Dict[int, Dict[str, Any]] = {}
        if os.path.exists(self.index_path):
            self.load()

    def save(self) -> None:
        faiss.write_index(self.index, self.index_path)
        with open(self.meta_path, "w") as f:
            json.dump(self.metadata, f)
        logger.info("Vector database saved")

    def load(self) -> None:
        self.index = faiss.read_index(self.index_path)
        self.index = faiss.IndexIDMap(self.index)
        with open(self.meta_path, "r") as f:
            self.metadata = {int(k): v for k, v in json.load(f).items()}
        logger.info("Vector database loaded (%d vectors)", self.index.ntotal)

    def add_documents(self, docs: List[Dict[str, Any]]):
        if not docs:
            return
        texts = [json.dumps(doc, sort_keys=True) for doc in docs]
        embeddings = self.model.encode(texts, convert_to_numpy=True)
        ids = []
        new_docs = []
        for emb, doc in zip(embeddings, docs):
            sha = hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()
            doc_id = int(sha[:16], 16)
            if doc_id in self.metadata:
                continue
            ids.append(np.int64(doc_id))
            new_docs.append(emb)
            self.metadata[doc_id] = doc
        if new_docs:
            self.index.add_with_ids(np.vstack(new_docs), np.array(ids))
            logger.info("Added %d documents to vector DB", len(new_docs))

    def search(self, query: str, k: int = 5) -> List[Dict[str, Any]]:
        if self.index.ntotal == 0:
            return []
        q_emb = self.model.encode([query], convert_to_numpy=True)
        distances, ids = self.index.search(q_emb, k)
        results = []
        for i in ids[0]:
            if i in self.metadata:
                results.append(self.metadata[i])
        return results
