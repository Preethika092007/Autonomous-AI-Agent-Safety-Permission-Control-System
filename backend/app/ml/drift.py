import os
import json
import time
import threading
import numpy as np
from typing import Dict, Any, List, Tuple
from app.ml.vectorizer import AuraVectorizer
from app.core.config import settings

class DriftMonitor:
    def __init__(self, vectorizer=None):
        self.lock = threading.Lock()
        # Elements: (timestamp, risk_level, decision, embedding_norm, text_length, agent_id, model_version)
        self.history: List[Tuple[float, str, str, float, int, str, str]] = []
        
        # Baseline expected distributions
        self.expected_text_lengths = []
        self.expected_embedding_norms = []
        self.expected_risk_levels = []
        
        # Initialize baseline
        self._load_baseline(vectorizer)

    def _load_baseline(self, vectorizer):
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            dataset_path = os.path.join(base_dir, "dataset_v1.json")
            if not os.path.exists(dataset_path):
                # Fallback default uniform expected distributions
                self.expected_text_lengths = [0.2] * 5
                self.expected_embedding_norms = [0.25] * 4
                self.expected_risk_levels = [0.33, 0.33, 0.34]
                return
                
            with open(dataset_path, "r") as f:
                data = json.load(f)
                
            lengths = []
            norms = []
            risks = []
            
            # We need a vectorizer to compute baseline norms
            if vectorizer is None:
                vectorizer = AuraVectorizer()
                
            texts = []
            for item in data:
                action = item["action"]
                params = item["parameters"]
                text = f"action: {action} | parameters: {json.dumps(params)}"
                texts.append(text)
                lengths.append(len(text))
                risks.append(item["expected_risk_level"].lower())
                
            # Vectorize to get norms
            vectors = vectorizer.encode(texts)
            for vec in vectors:
                norms.append(float(np.linalg.norm(vec)))
                
            # Compute baseline distributions
            self.expected_text_lengths = self._bucket_text_lengths(lengths)
            self.expected_embedding_norms = self._bucket_embedding_norms(norms)
            self.expected_risk_levels = self._bucket_categorical(risks, ["low", "medium", "high"])
        except Exception:
            # Log warning and set fallbacks
            self.expected_text_lengths = [0.2] * 5
            self.expected_embedding_norms = [0.25] * 4
            self.expected_risk_levels = [0.33, 0.33, 0.34]

    def _bucket_text_lengths(self, lengths: List[int]) -> List[float]:
        # Buckets: <30, 30-60, 60-120, 120-240, 240+
        counts = [0] * 5
        for l in lengths:
            if l < 30:
                counts[0] += 1
            elif l < 60:
                counts[1] += 1
            elif l < 120:
                counts[2] += 1
            elif l < 240:
                counts[3] += 1
            else:
                counts[4] += 1
        total = len(lengths) or 1
        return [c / total for c in counts]

    def _bucket_embedding_norms(self, norms: List[float]) -> List[float]:
        # Buckets: <0.9, 0.9-1.0, 1.0-1.1, 1.1+
        counts = [0] * 4
        for n in norms:
            if n < 0.9:
                counts[0] += 1
            elif n < 1.0:
                counts[1] += 1
            elif n < 1.1:
                counts[2] += 1
            else:
                counts[3] += 1
        total = len(norms) or 1
        return [c / total for c in counts]

    def _bucket_categorical(self, items: List[str], categories: List[str]) -> List[float]:
        counts = [0] * len(categories)
        for item in items:
            if item in categories:
                idx = categories.index(item)
                counts[idx] += 1
        total = len(items) or 1
        return [c / total for c in counts]

    def record_inference(self, risk_level: str, decision: str, embedding_norm: float, text_length: int, agent_id: str, model_version: str):
        with self.lock:
            now = time.time()
            self.history.append((
                now,
                risk_level.lower(),
                decision.lower(),
                embedding_norm,
                text_length,
                agent_id,
                model_version
            ))
            # Clean up history older than 24 hours
            cutoff = now - 86400
            self.history = [h for h in self.history if h[0] >= cutoff]

    def get_aggregated_stats(self, window_seconds: int) -> Dict[str, Any]:
        with self.lock:
            now = time.time()
            cutoff = now - window_seconds
            recent = [h for h in self.history if h[0] >= cutoff]
            
        total_requests = len(recent)
        if total_requests == 0:
            return {
                "request_count": 0,
                "risk_level_distribution": {"low": 0, "medium": 0, "high": 0},
                "policy_decision_distribution": {"allow": 0, "require_human_approval": 0, "block": 0},
                "avg_embedding_norm": 0.0,
                "action_text_length_buckets": [0] * 5,
                "per_agent_volume": {},
                "model_version_volume": {}
            }
            
        risk_counts = {"low": 0, "medium": 0, "high": 0}
        decision_counts = {"allow": 0, "require_human_approval": 0, "block": 0}
        total_norm = 0.0
        length_counts = [0] * 5
        agent_counts = {}
        version_counts = {}
        
        for h in recent:
            _, risk, dec, norm, length, agent, version = h
            
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            decision_counts[dec] = decision_counts.get(dec, 0) + 1
            total_norm += norm
            
            # Text length buckets
            if length < 30:
                length_counts[0] += 1
            elif length < 60:
                length_counts[1] += 1
            elif length < 120:
                length_counts[2] += 1
            elif length < 240:
                length_counts[3] += 1
            else:
                length_counts[4] += 1
                
            agent_counts[agent] = agent_counts.get(agent, 0) + 1
            version_counts[version] = version_counts.get(version, 0) + 1
            
        return {
            "request_count": total_requests,
            "risk_level_distribution": risk_counts,
            "policy_decision_distribution": decision_counts,
            "avg_embedding_norm": total_norm / total_requests,
            "action_text_length_buckets": length_counts,
            "per_agent_volume": agent_counts,
            "model_version_volume": version_counts
        }

    def calculate_psi(self, window_seconds: int = 3600) -> Tuple[float, str]:
        # Returns: (psi_score, drift_status)
        # Default window is 1 hour
        stats = self.get_aggregated_stats(window_seconds)
        total = stats["request_count"]
        if total < 5:
            # Too few samples to calculate reliable PSI, return normal
            return 0.0, "normal"
            
        # Compute actual probabilities
        actual_lengths = [c / total for c in stats["action_text_length_buckets"]]
        
        # Calculate PSI
        # PSI = sum((Actual - Expected) * ln(Actual / Expected))
        psi = 0.0
        epsilon = 1e-4
        for act, exp in zip(actual_lengths, self.expected_text_lengths):
            act = max(act, epsilon)
            exp = max(exp, epsilon)
            psi += (act - exp) * np.log(act / exp)
            
        # Determine status
        if psi >= settings.ML_DRIFT_CRITICAL_THRESHOLD:
            status = "critical"
        elif psi >= settings.ML_DRIFT_WARNING_THRESHOLD:
            status = "warning"
        else:
            status = "normal"
            
        return float(psi), status
