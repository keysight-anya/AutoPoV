"""
AutoPoV Code Ingestion Module
Handles code chunking, embedding, and ChromaDB storage for RAG
"""

import os
import re
import math
import hashlib
from typing import List, Dict, Optional, Iterator, Callable
from pathlib import Path

from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False

try:
    from langchain_openai import OpenAIEmbeddings
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    from langchain_huggingface import HuggingFaceEmbeddings
    HUGGINGFACE_AVAILABLE = True
except ImportError:
    HUGGINGFACE_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False

from app.config import settings


class CodeIngestionError(Exception):
    """Exception raised during code ingestion"""
    pass



class _SentenceTransformerEmbeddings:
    """Minimal embeddings wrapper backed by sentence-transformers."""

    def __init__(self, model_name: str):
        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            raise CodeIngestionError("sentence-transformers not available for local embedding fallback")
        self._model = SentenceTransformer(model_name)

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        vectors = self._model.encode(texts, convert_to_numpy=False, show_progress_bar=False)
        return [_coerce_embedding_vector(vector) for vector in vectors]

    def embed_query(self, text: str) -> List[float]:
        vector = self._model.encode(text, convert_to_numpy=False, show_progress_bar=False)
        return _coerce_embedding_vector(vector)


def _coerce_embedding_vector(vector) -> List[float]:
    """Normalize embedding outputs into plain Python float lists for Chroma."""
    if hasattr(vector, "tolist"):
        vector = vector.tolist()
    return [float(value) for value in vector]


def _coerce_embedding_batch(vectors) -> List[List[float]]:
    """Normalize a batch of embeddings into Chroma-compatible lists."""
    return [_coerce_embedding_vector(vector) for vector in vectors]


class _HashEmbeddings:
    """Lightweight local embeddings backend with no external model downloads."""

    def __init__(self, dimensions: int = 256):
        self.dimensions = dimensions

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,63}", text.lower())

    def _embed(self, text: str) -> List[float]:
        vector = [0.0] * self.dimensions
        tokens = self._tokenize(text)
        if not tokens:
            return vector
        for token in tokens:
            digest = hashlib.sha256(token.encode()).digest()
            bucket = int.from_bytes(digest[:4], 'big') % self.dimensions
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vector[bucket] += sign
        norm = math.sqrt(sum(value * value for value in vector)) or 1.0
        return [value / norm for value in vector]

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return [self._embed(text) for text in texts]

    def embed_query(self, text: str) -> List[float]:
        return self._embed(text)

class CodeIngester:
    """Handles ingestion of codebases into vector store"""
    
    def __init__(self):
        self.chunk_size = settings.MAX_CHUNK_SIZE
        self.chunk_overlap = settings.CHUNK_OVERLAP
        self.collection_name = settings.CHROMA_COLLECTION_NAME
        self.persist_dir = settings.CHROMA_PERSIST_DIR
        
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap,
            separators=["\nclass ", "\ndef ", "\nfunction ", "\n//", "\n#", "\n", " ", ""]
        )
        
        self._chroma_client = None
        self._collection = None
        self._embeddings = None
    
    def _build_local_embeddings(self):
        """Build a local embeddings backend for offline use or online fallback."""
        backend = (settings.LOCAL_EMBEDDING_BACKEND or "hash").lower()
        model_name = settings.EMBEDDING_MODEL_OFFLINE

        if backend == "hash":
            return _HashEmbeddings()

        if backend == "huggingface" and HUGGINGFACE_AVAILABLE:
            return HuggingFaceEmbeddings(model_name=model_name)

        if backend in {"sentence-transformers", "sentence_transformers"} and SENTENCE_TRANSFORMERS_AVAILABLE:
            return _SentenceTransformerEmbeddings(model_name)

        if HUGGINGFACE_AVAILABLE:
            return HuggingFaceEmbeddings(model_name=model_name)

        if SENTENCE_TRANSFORMERS_AVAILABLE:
            return _SentenceTransformerEmbeddings(model_name)

        return _HashEmbeddings()

    def _get_embeddings(self):
        """Get embeddings model based on configuration"""
        if self._embeddings is not None:
            return self._embeddings
        
        llm_config = settings.get_llm_config()
        
        if settings.PREFER_LOCAL_EMBEDDINGS:
            print(f"Info: Using local embeddings backend ({settings.LOCAL_EMBEDDING_BACKEND}) for ingestion.")
            self._embeddings = self._build_local_embeddings()
            return self._embeddings

        if llm_config["mode"] == "online":
            if not OPENAI_AVAILABLE:
                self._embeddings = self._build_local_embeddings()
                return self._embeddings

            api_key = llm_config.get("api_key")
            if not api_key:
                self._embeddings = self._build_local_embeddings()
                return self._embeddings

            embedding_model = llm_config["embedding_model"]

            try:
                self._embeddings = OpenAIEmbeddings(
                    model=embedding_model,
                    api_key=api_key,
                    base_url=llm_config["base_url"],
                    default_headers={
                        "HTTP-Referer": "https://autopov.local",
                        "X-OpenRouter-Title": "AutoPoV"
                    }
                )
                self._embeddings.embed_query("autopov")
            except Exception as exc:
                print(f"Warning: Online embeddings unavailable ({exc}). Falling back to local embeddings.")
                self._embeddings = self._build_local_embeddings()
        else:
            print(f"Info: Using local embeddings backend ({settings.LOCAL_EMBEDDING_BACKEND}) for ingestion.")
            self._embeddings = self._build_local_embeddings()
        
        return self._embeddings
    
    def _get_chroma_client(self):
        """Get or create ChromaDB client"""
        if not CHROMADB_AVAILABLE:
            raise CodeIngestionError("ChromaDB not available. Install chromadb")
        
        if self._chroma_client is None:
            self._chroma_client = chromadb.PersistentClient(
                path=self.persist_dir,
                settings=Settings(
                    anonymized_telemetry=False
                )
            )
        
        return self._chroma_client
    
    def _get_collection(self, scan_id: str):
        """Get or create collection for scan"""
        client = self._get_chroma_client()
        collection_name = f"{self.collection_name}_{scan_id}"
        
        try:
            collection = client.get_collection(name=collection_name)
        except Exception:
            collection = client.create_collection(name=collection_name)
        
        return collection
    
    def _generate_doc_id(self, content: str, filepath: str, chunk_idx: int) -> str:
        """Generate unique document ID"""
        content_hash = hashlib.md5(content.encode()).hexdigest()[:12]
        return f"{filepath}:{chunk_idx}:{content_hash}"
    
    def _is_code_file(self, filepath: str) -> bool:
        """Check if file is a code file we should process"""
        code_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.cc',
            '.h', '.hpp', '.go', '.rs', '.rb', '.php', '.cs', '.swift', '.kt',
            '.scala', '.r', '.m', '.mm', '.pl', '.sh', '.sql'
        }
        ext = os.path.splitext(filepath)[1].lower()
        return ext in code_extensions
    
    def _is_binary(self, filepath: str, chunk_size: int = 1024) -> bool:
        """Check if file is binary"""
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(chunk_size)
                return b'\0' in chunk
        except Exception:
            return True
    
    def _read_file(self, filepath: str) -> Optional[str]:
        """Read file content"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"Warning: Could not read {filepath}: {e}")
            return None
    
    def _chunk_code(self, content: str, filepath: str) -> List[Document]:
        """Split code into chunks"""
        documents = []
        
        # Add file metadata
        metadata = {
            "source": filepath,
            "filepath": filepath,
            "language": self._detect_language(filepath)
        }
        
        # Split into chunks
        chunks = self.text_splitter.create_documents(
            texts=[content],
            metadatas=[metadata]
        )
        
        return chunks
    
    def _detect_language(self, filepath: str) -> str:
        """Detect programming language from file extension"""
        ext = os.path.splitext(filepath)[1].lower()
        lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.h': 'c',
            '.hpp': 'cpp',
            '.go': 'go',
            '.rs': 'rust',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.scala': 'scala',
            '.r': 'r',
            '.m': 'objective-c',
            '.mm': 'objective-cpp',
            '.pl': 'perl',
            '.sh': 'shell',
            '.sql': 'sql'
        }
        return lang_map.get(ext, 'unknown')
    
    def ingest_directory(
        self,
        directory: str,
        scan_id: str,
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, any]:
        """
        Ingest all code files from a directory
        
        Args:
            directory: Path to directory containing code
            scan_id: Unique scan identifier
            progress_callback: Optional callback for progress updates
        
        Returns:
            Dictionary with ingestion statistics
        """
        if not CHROMADB_AVAILABLE:
            raise CodeIngestionError("ChromaDB not available")
        
        stats = {
            "files_processed": 0,
            "files_skipped": 0,
            "chunks_created": 0,
            "errors": []
        }
        
        # Get collection
        collection = self._get_collection(scan_id)
        
        # Get embeddings
        embeddings = self._get_embeddings()
        
        # Process all files
        all_chunks = []
        all_ids = []
        all_documents = []
        all_metadatas = []
        
        for root, dirs, files in os.walk(directory):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for filename in files:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, directory)
                
                # Skip non-code files
                if not self._is_code_file(filepath):
                    stats["files_skipped"] += 1
                    continue
                
                # Skip binary files
                if self._is_binary(filepath):
                    stats["files_skipped"] += 1
                    continue
                
                # Read file
                content = self._read_file(filepath)
                if content is None:
                    stats["errors"].append(f"Could not read: {rel_path}")
                    continue
                
                # Skip empty files
                if not content.strip():
                    stats["files_skipped"] += 1
                    continue
                
                # Chunk the code
                try:
                    chunks = self._chunk_code(content, rel_path)
                    
                    for idx, chunk in enumerate(chunks):
                        doc_id = self._generate_doc_id(chunk.page_content, rel_path, idx)
                        
                        all_chunks.append(chunk.page_content)
                        all_ids.append(doc_id)
                        all_documents.append(chunk.page_content)
                        all_metadatas.append(chunk.metadata)
                    
                    stats["files_processed"] += 1
                    stats["chunks_created"] += len(chunks)
                    
                    if progress_callback:
                        progress_callback(stats["files_processed"], rel_path)
                
                except Exception as e:
                    stats["errors"].append(f"Error processing {rel_path}: {str(e)}")
        
        # Add to ChromaDB in batches
        batch_size = 100
        for i in range(0, len(all_chunks), batch_size):
            batch_end = min(i + batch_size, len(all_chunks))
            
            # Generate embeddings for batch
            batch_texts = all_chunks[i:batch_end]
            batch_embeddings = _coerce_embedding_batch(embeddings.embed_documents(batch_texts))
            
            # Add to collection
            collection.add(
                ids=all_ids[i:batch_end],
                embeddings=batch_embeddings,
                documents=all_documents[i:batch_end],
                metadatas=all_metadatas[i:batch_end]
            )
        
        return stats
    
    def retrieve_context(
        self,
        query: str,
        scan_id: str,
        top_k: int = 5
    ) -> List[Dict[str, any]]:
        """
        Retrieve relevant code context for a query
        
        Args:
            query: Query text (e.g., vulnerability description)
            scan_id: Unique scan identifier
            top_k: Number of results to return
        
        Returns:
            List of relevant code chunks with metadata
        """
        if not CHROMADB_AVAILABLE:
            raise CodeIngestionError("ChromaDB not available")
        
        # Get collection
        collection = self._get_collection(scan_id)
        
        # Get embeddings
        embeddings = self._get_embeddings()
        query_embedding = _coerce_embedding_vector(embeddings.embed_query(query))
        
        # Query collection
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k
        )
        
        # Format results
        formatted_results = []
        for i in range(len(results["ids"][0])):
            formatted_results.append({
                "id": results["ids"][0][i],
                "content": results["documents"][0][i],
                "metadata": results["metadatas"][0][i],
                "distance": results["distances"][0][i] if "distances" in results else None
            })
        
        return formatted_results
    
    def get_file_content(
        self,
        filepath: str,
        scan_id: str
    ) -> Optional[str]:
        """
        Get full content of a file from the collection
        
        Args:
            filepath: Relative file path
            scan_id: Unique scan identifier
        
        Returns:
            File content or None if not found
        """
        if not CHROMADB_AVAILABLE:
            raise CodeIngestionError("ChromaDB not available")
        
        # Get collection
        collection = self._get_collection(scan_id)
        
        # Query for file chunks
        results = collection.get(
            where={"filepath": filepath}
        )
        
        if not results["documents"]:
            return None
        
        # Combine chunks (they should be in order)
        content = "\n".join(results["documents"])
        return content
    
    def cleanup(self, scan_id: str):
        """Clean up collection for a scan"""
        if not CHROMADB_AVAILABLE:
            return
        
        try:
            client = self._get_chroma_client()
            collection_name = f"{self.collection_name}_{scan_id}"
            client.delete_collection(name=collection_name)
        except Exception as e:
            print(f"Warning: Could not cleanup collection for {scan_id}: {e}")


# Global code ingester instance
code_ingester = CodeIngester()


def get_code_ingester() -> CodeIngester:
    """Get the global code ingester instance"""
    return code_ingester
