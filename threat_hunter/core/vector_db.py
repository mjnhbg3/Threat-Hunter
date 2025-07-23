
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from threat_hunter.utils.logger import logger

class VectorDB:
    def __init__(self, model_name='all-MiniLM-L6-v2', dimension=384):
        self.model = SentenceTransformer(model_name)
        self.dimension = dimension
        self.index = faiss.IndexFlatL2(dimension)
        self.doc_store = []

    def add_documents(self, documents):
        embeddings = self.model.encode(documents)
        self.index.add(embeddings)
        self.doc_store.extend(documents)

    def search(self, query, k=5):
        query_embedding = self.model.encode([query])
        distances, indices = self.index.search(query_embedding, k)
        return [self.doc_store[i] for i in indices[0]]

    def save(self, index_path, doc_store_path):
        faiss.write_index(self.index, index_path)
        with open(doc_store_path, 'w') as f:
            json.dump(self.doc_store, f)

    def load(self, index_path, doc_store_path):
        self.index = faiss.read_index(index_path)
        with open(doc_store_path, 'r') as f:
            self.doc_store = json.load(f)
