import os
import re
import json
import hashlib
import logging
import threading
from datetime import datetime, timezone
import numpy as np
import xgboost as xgb
import shap
from app.ml.vectorizer import AuraVectorizer
from app.core.config import settings
from app.core.metrics import (
    model_load_errors_counter,
    model_checksum_failures_counter,
    model_sync_status_gauge,
    model_evaluations_counter
)

logger = logging.getLogger("aura.ml")

class RiskEngineError(Exception):
    """Custom exception raised when the risk engine safety validation fails."""
    pass

class RiskEngine:
    def __init__(self, model_path=None):
        self._lock = threading.Lock()
        self.model = None
        self.explainer = None
        self.metadata = None
        self.model_version = None
        self.feature_schema_version = None
        self.sync_status = "unavailable"  # synchronized, degraded, unavailable
        
        # Load directories
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.registry_dir = os.path.join(base_dir, "registry")
        self.forced_model_path = model_path
        
        # Initialize Vectorizer
        logger.info("Loading ML vectorizer...")
        self.vectorizer = AuraVectorizer()
        logger.info("ML vectorizer loaded.")

        # Initialize Drift Monitor
        from app.ml.drift import DriftMonitor
        self.drift_monitor = DriftMonitor(self.vectorizer)
        
        # Initial load and validation
        self.reload_active_model()

    def _compute_sha256(self, file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def reload_active_model(self):
        """
        Loads the active model from the database, or seeds default model version 1.0.0
        on fresh installations. Operates thread-safely.
        """
        from app.core.database import SessionLocal
        from app.models import ModelRegistry, ModelAuditEvent

        db = SessionLocal()
        target_version = settings.ML_MODEL_VERSION
        target_ubj = os.path.join(self.registry_dir, f"aura-risk-model_{target_version}.ubj")
        expected_sha = None
        expected_schema = 1

        try:
            # 1. Automatic Seeding for fresh databases
            if settings.MODEL_GOVERNANCE_ENABLED:
                try:
                    active_model = db.query(ModelRegistry).filter(ModelRegistry.status == "active").first()
                    if not active_model:
                        # Fallback check: if default 1.0.0 exists, seed it
                        default_ver = settings.ML_MODEL_VERSION
                        default_ubj = os.path.join(self.registry_dir, f"aura-risk-model_{default_ver}.ubj")
                        default_json = os.path.join(self.registry_dir, f"aura-risk-model_{default_ver}.json")
                        
                        if os.path.exists(default_ubj) and os.path.exists(default_json):
                            with open(default_json, "r") as f:
                                meta = json.load(f)
                            
                            sha = self._compute_sha256(default_ubj)
                            
                            # Create DB registry record
                            new_model = ModelRegistry(
                                model_version=default_ver,
                                feature_schema_version=1,
                                dataset_version="1.0.0",
                                artifact_path=default_ubj,
                                sha256=sha,
                                status="active",
                                metrics_json=meta.get("metrics", {}),
                                activated_at=datetime.utcnow()
                            )
                            db.add(new_model)
                            db.commit()
                            
                            # Create audit events
                            audit_reg = ModelAuditEvent(
                                model_version=default_ver,
                                event_type="registered",
                                reason="Default model seeded on startup",
                                success=True
                            )
                            db.add(audit_reg)
                            
                            audit_act = ModelAuditEvent(
                                model_version=default_ver,
                                event_type="activated",
                                reason="Default model activated on startup",
                                success=True
                            )
                            db.add(audit_act)
                            db.commit()
                            
                            logger.info(f"Seeded default model version {default_ver} into database registry.")
                            active_model = new_model
                except Exception as db_err:
                    logger.error(f"Seeding models into database failed: {db_err}")

            # 2. Identify target model
            if self.forced_model_path:
                target_ubj = self.forced_model_path
                target_json = self.forced_model_path.replace(".ubj", ".json")
                if os.path.exists(target_json):
                    with open(target_json, "r") as f:
                        meta = json.load(f)
                    target_version = meta.get("version", "forced")
                else:
                    target_version = "forced"
            elif settings.MODEL_GOVERNANCE_ENABLED:
                try:
                    active_model = db.query(ModelRegistry).filter(ModelRegistry.status == "active").first()
                    if active_model:
                        target_version = active_model.model_version
                        target_ubj = active_model.artifact_path
                        expected_sha = active_model.sha256
                        expected_schema = active_model.feature_schema_version
                except Exception as db_err:
                    logger.error(f"Failed querying active model from database: {db_err}")

            # 3. Handle file existence / fallbacks
            target_json = target_ubj.replace(".ubj", ".json")
            if not os.path.exists(target_ubj) or not os.path.exists(target_json):
                if settings.ENV == "production":
                    msg = f"Critical Startup Error: Model files missing for version {target_version} at {target_ubj}."
                    logger.error(msg)
                    raise RiskEngineError(msg)
                else:
                    logger.warning(f"Model files missing for version {target_version}. Triggering dynamic training...")
                    from app.ml.train import train_model
                    train_model(version=target_version)
                    if not os.path.exists(target_ubj):
                        raise RiskEngineError(f"Dynamic training failed to produce booster file at {target_ubj}.")

            # 4. Integrity Checks
            actual_sha = self._compute_sha256(target_ubj)
            if expected_sha and actual_sha != expected_sha:
                model_checksum_failures_counter.labels(model_version=target_version).inc()
                msg = f"Integrity Failure: Checksum mismatch for model {target_version}."
                logger.error(msg)
                raise RiskEngineError(msg)

            # 5. Schema verification
            if expected_schema != 1:
                msg = f"Incompatibility: Feature schema version {expected_schema} is incompatible with engine."
                logger.error(msg)
                raise RiskEngineError(msg)

            # 6. Load metadata JSON first to verify integrity (Phase 5 compatibility)
            with open(target_json, "r") as f:
                temp_metadata = json.load(f)

            expected_sha_file = temp_metadata.get("sha256_checksum")
            if expected_sha_file and actual_sha != expected_sha_file:
                model_checksum_failures_counter.labels(model_version=target_version).inc()
                msg = f"Integrity Failure: Model checksum mismatch (expected: {expected_sha_file}, actual: {actual_sha})."
                logger.error(msg)
                raise RiskEngineError(msg)

            # Now load booster & SHAP explainer safely
            temp_model = xgb.XGBClassifier()
            temp_model.load_model(target_ubj)
            temp_explainer = shap.TreeExplainer(temp_model)

            # 7. Atomically Swap active model properties under lock
            with self._lock:
                self.model = temp_model
                self.explainer = temp_explainer
                self.metadata = temp_metadata
                self.model_version = target_version
                self.feature_schema_version = expected_schema
                self.sync_status = "synchronized"

            model_sync_status_gauge.labels(model_version=target_version).set(1)
            logger.info(f"Atomically loaded model version {target_version} successfully.")
        except Exception as e:
            model_load_errors_counter.labels(model_version=target_version).inc()
            model_sync_status_gauge.labels(model_version=target_version).set(0)
            logger.error(f"Error loading model: {e}")
            with self._lock:
                if self.model is None:
                    self.sync_status = "unavailable"
                    if settings.ML_FAIL_CLOSED:
                        raise RiskEngineError(f"ML Startup load error (fail-closed): {e}")
                else:
                    self.sync_status = "degraded"
        finally:
            db.close()

    def _deterministic_pre_filter(self, action: str, parameters: dict):
        text_to_check = f"{action} {json.dumps(parameters)}".lower()
        
        catastrophic_patterns = {
            r"rm\s+-rf": "Blocked execution of potentially catastrophic file deletion command (rm -rf).",
            r"drop\s+table": "Blocked SQL injection attempt: database table destruction command (DROP TABLE) detected.",
            r"/etc/passwd": "Blocked unauthorized local file inclusion/access attempt to system passwd file (/etc/passwd).",
            r"format\s+[a-zA-Z]:": "Blocked drive formatting request."
        }
        
        for pattern, reason in catastrophic_patterns.items():
            if re.search(pattern, text_to_check):
                return "high", "block", f"Risk HIGH (Deterministic Rules): {reason}"
                
        return None

    def evaluate(self, action: str, parameters: dict, agent_id: str = "unknown"):
        # Fail-closed wrapper
        try:
            return self._evaluate_internal(action, parameters, agent_id)
        except Exception as e:
            logger.error(f"Risk evaluation failure: {e}", exc_info=True)
            if settings.ML_FAIL_CLOSED:
                raise RiskEngineError(f"Safety system failure during ML inference (fail-closed): {e}")
            return "high", "block", f"ML Inference Error: safety override (fail-closed)."

    def _evaluate_internal(self, action: str, parameters: dict, agent_id: str):
        # 1. Deterministic Rule Pre-filter
        pre_filter_result = self._deterministic_pre_filter(action, parameters)
        if pre_filter_result:
            return pre_filter_result

        # Ensure model is initialized
        if self.model is None:
            raise RiskEngineError("Model not loaded.")

        # 2. Extract NLP Embeddings
        input_text = f"action: {action} | parameters: {json.dumps(parameters)}"
        vector = self.vectorizer.encode([input_text])

        # 3. XGBoost Inference
        with self._lock:
            pred_probs = self.model.predict_proba(vector)[0]
            current_version = self.model_version

        # Increment evaluations counter
        model_evaluations_counter.labels(model_version=current_version).inc()

        # Threshold-based predictions
        # 0 = low, 1 = medium, 2 = high
        prob_high = float(pred_probs[2])
        prob_med = float(pred_probs[1])
        
        if prob_high >= settings.ML_HIGH_RISK_THRESHOLD:
            pred_class = 2
        elif prob_med >= settings.ML_MEDIUM_RISK_THRESHOLD:
            pred_class = 1
        else:
            pred_class = 0
            
        risk_mapping = {0: "low", 1: "medium", 2: "high"}
        decision_mapping = {"low": "allow", "medium": "require_human_approval", "high": "block"}
        
        risk_level = risk_mapping[pred_class]
        decision = decision_mapping[risk_level]
        confidence = float(pred_probs[pred_class])

        # Record inference statistics for drift detection
        if settings.ML_DRIFT_MONITORING_ENABLED:
            norm_val = float(np.linalg.norm(vector[0]))
            self.drift_monitor.record_inference(
                risk_level=risk_level,
                decision=decision,
                embedding_norm=norm_val,
                text_length=len(input_text),
                agent_id=agent_id,
                model_version=current_version
            )

        # 4. SHAP Feature Attribution with Safeguards
        top_dims = []
        shap_explanation_available = True
        
        if len(input_text) > 1000:
            logger.warning("Skipping SHAP explanation: Input text length exceeds 1000 characters safeguard limit.")
            shap_explanation_available = False
        else:
            try:
                with self._lock:
                    shap_vals = self.explainer.shap_values(vector)
                
                if isinstance(shap_vals, list):
                    class_shap = shap_vals[pred_class][0]
                else:
                    if len(shap_vals.shape) == 3:
                        class_shap = shap_vals[0, :, pred_class]
                    else:
                        class_shap = shap_vals[0]
                
                top_dims = np.argsort(np.abs(class_shap))[-3:][::-1]
            except Exception as e:
                logger.warning(f"SHAP explanation generation failed (fallback to empty reasons): {e}")
                shap_explanation_available = False

        # 5. Parameter Omission Perturbation
        parameter_contributions = []
        if parameters:
            base_prob = pred_probs[pred_class]
            for key, val in parameters.items():
                temp_params = parameters.copy()
                temp_params.pop(key)
                
                temp_text = f"action: {action} | parameters: {json.dumps(temp_params)}"
                temp_vec = self.vectorizer.encode([temp_text])
                with self._lock:
                    temp_probs = self.model.predict_proba(temp_vec)[0]
                temp_prob = temp_probs[pred_class]
                
                diff = base_prob - temp_prob
                parameter_contributions.append((key, val, diff))

        # Format mathematical explanation reason string
        reason = f"Risk {risk_level.upper()} (ML Model): XGBoost classification (confidence {confidence:.1%})."
        
        if parameter_contributions:
            parameter_contributions.sort(key=lambda x: abs(x[2]), reverse=True)
            top_param = parameter_contributions[0]
            pct_impact = abs(top_param[2]) * 100
            reason += f" The parameter '{top_param[0]}' with value '{top_param[1]}' contributed {pct_impact:.1f}% to the threat score."
        
        if shap_explanation_available and len(top_dims) > 0:
            reason += f" [SHAP vector features: {top_dims.tolist()}]"
        else:
            reason += " [SHAP explanation unavailable]"

        return risk_level, decision, reason
