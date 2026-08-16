import os
import logging
import numpy as np

logger = logging.getLogger("aura.ml")

class AuraVectorizer:
    def __init__(self):
        self._use_fastembed = False
        self._model = None

        # Enforce PyTorch CPU single-threaded allocations early
        os.environ["OMP_NUM_THREADS"] = "1"
        os.environ["MKL_NUM_THREADS"] = "1"
        os.environ["OPENBLAS_NUM_THREADS"] = "1"
        os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
        os.environ["NUMEXPR_NUM_THREADS"] = "1"
        try:
            import torch
            torch.set_num_threads(1)
            torch.set_grad_enabled(False)
        except ImportError:
            pass

        # Try to load fastembed (ONNX runtime, uses < 100MB RAM)
        try:
            from fastembed import TextEmbedding
            logger.info("Initializing fastembed TextEmbedding (all-MiniLM-L6-v2) for low RAM footprint...")
            self._model = TextEmbedding("sentence-transformers/all-MiniLM-L6-v2")
            self._use_fastembed = True
            logger.info("fastembed TextEmbedding successfully loaded.")
        except Exception as e:
            logger.warning(f"Could not load fastembed: {e}. Falling back to sentence-transformers (PyTorch)...")
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer("all-MiniLM-L6-v2")
                self._use_fastembed = False
                logger.info("SentenceTransformer (PyTorch) fallback successfully loaded.")
            except Exception as ex:
                logger.error(f"Critical error initializing all vectorizers: {ex}")
                raise ex

        import gc
        gc.collect()

    def encode(self, texts):
        if isinstance(texts, str):
            texts = [texts]
        if self._use_fastembed:
            # fastembed returns generator of 1D numpy arrays. Convert to 2D matrix
            embeddings = list(self._model.embed(texts))
            return np.array(embeddings)
        else:
            return self._model.encode(texts)
