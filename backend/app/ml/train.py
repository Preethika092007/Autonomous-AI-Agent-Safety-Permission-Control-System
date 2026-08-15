import os
import sys
import json
import hashlib
from datetime import datetime, timezone
import numpy as np
import xgboost as xgb
from sentence_transformers import SentenceTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

def compute_sha256(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def train_model(version: str = "1.0.0", dataset_path: str = None):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    if dataset_path is None:
        dataset_path = os.path.join(base_dir, "dataset_v1.json")
    
    registry_dir = os.path.join(base_dir, "registry")
    os.makedirs(registry_dir, exist_ok=True)
    
    print(f"Loading training dataset from {dataset_path}...")
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        sys.exit(1)
        
    with open(dataset_path, "r") as f:
        data = json.load(f)
        
    print(f"Loaded {len(data)} examples.")
    
    # 1. Validate dataset fields
    required_keys = {"action", "parameters", "agent_role", "expected_risk_level"}
    for idx, item in enumerate(data):
        missing = required_keys - item.keys()
        if missing:
            print(f"Error: Dataset item at index {idx} is missing keys: {missing}")
            sys.exit(1)
            
    # 2. Map risk levels to labels
    # 0 = low, 1 = medium, 2 = high
    risk_mapping = {"low": 0, "medium": 1, "high": 2}
    
    texts = []
    labels = []
    dataset_version = "unknown"
    for item in data:
        action = item["action"]
        params = item["parameters"]
        risk_str = item["expected_risk_level"].lower()
        if risk_str not in risk_mapping:
            print(f"Error: Invalid risk level '{risk_str}' in dataset.")
            sys.exit(1)
        labels.append(risk_mapping[risk_str])
        
        # Consistent text serialization format (feature schema 1)
        text = f"action: {action} | parameters: {json.dumps(params)}"
        texts.append(text)
        
        if "dataset_version" in item:
            dataset_version = item["dataset_version"]

    X_texts = np.array(texts)
    y = np.array(labels)
    
    # 3. Deterministic train/val/test splitting
    # Fixed random seed to ensure reproducibility
    X_train_t, X_temp_t, y_train, y_temp = train_test_split(
        X_texts, y, test_size=0.3, random_state=42, stratify=y
    )
    X_val_t, X_test_t, y_val, y_test = train_test_split(
        X_temp_t, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )
    
    print(f"Split sizes -> Train: {len(X_train_t)}, Val: {len(X_val_t)}, Test: {len(X_test_t)}")
    
    # 4. Vectorize text features using SentenceTransformer
    print("Loading SentenceTransformer model 'all-MiniLM-L6-v2'...")
    vectorizer = SentenceTransformer("all-MiniLM-L6-v2")
    
    print("Vectorizing train/val splits...")
    X_train = vectorizer.encode(X_train_t.tolist())
    X_val = vectorizer.encode(X_val_t.tolist())
    
    # 5. Train model
    print("Training XGBoost Classifier...")
    hyperparams = {
        "objective": "multi:softprob",
        "num_class": 3,
        "max_depth": 4,
        "learning_rate": 0.1,
        "n_estimators": 50,
        "eval_metric": "mlogloss",
        "random_state": 42
    }
    model = xgb.XGBClassifier(**hyperparams)
    model.fit(X_train, y_train)
    
    # 6. Evaluate model on Validation split
    print("Evaluating model...")
    y_pred = model.predict(X_val)
    y_pred_probs = model.predict_proba(X_val)
    
    accuracy = accuracy_score(y_val, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_val, y_pred, average="macro")
    cm = confusion_matrix(y_val, y_pred)
    
    # Calculate False Allow and False Block Rates
    # False Allow: True label = high (2), predicted = low (0)
    high_idx = np.where(y_val == 2)[0]
    if len(high_idx) > 0:
        false_allow_count = np.sum(y_pred[high_idx] == 0)
        false_allow_rate = float(false_allow_count / len(high_idx))
    else:
        false_allow_rate = 0.0
        
    # False Block: True label = low (0), predicted = high (2)
    low_idx = np.where(y_val == 0)[0]
    if len(low_idx) > 0:
        false_block_count = np.sum(y_pred[low_idx] == 2)
        false_block_rate = float(false_block_count / len(low_idx))
    else:
        false_block_rate = 0.0
        
    print(f"Validation Accuracy: {accuracy:.4f}")
    print(f"Validation F1-Score: {f1:.4f}")
    print(f"False Allow Rate: {false_allow_rate:.4f} (bypassed threats)")
    print(f"False Block Rate: {false_block_rate:.4f} (blocked safe actions)")
    
    # 7. Save model artifact
    model_filename = f"aura-risk-model_{version}.ubj"
    model_path = os.path.join(registry_dir, model_filename)
    model.save_model(model_path)
    print(f"Booster saved to: {model_path}")
    
    # 8. Checksum and Metadata
    sha256_checksum = compute_sha256(model_path)
    
    metadata = {
        "model_id": "aura-risk-model",
        "version": version,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "feature_schema_version": 1,
        "dataset_id": f"dataset_v1.json_v{dataset_version}",
        "algorithm": "xgboost",
        "hyperparameters": {k: v for k, v in hyperparams.items() if k != "objective" and k != "eval_metric"},
        "validation_metrics": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "false_allow_rate": false_allow_rate,
            "false_block_rate": false_block_rate,
            "confusion_matrix": cm.tolist()
        },
        "sha256_checksum": sha256_checksum,
        "approval_status": "APPROVED"
    }
    
    metadata_filename = f"aura-risk-model_{version}.json"
    metadata_path = os.path.join(registry_dir, metadata_filename)
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to: {metadata_path}")
    print("Model training pipeline completed successfully.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AURA Firewall ML Training Pipeline")
    parser.add_argument("--version", type=str, default="1.0.0", help="Version identifier for the trained model")
    parser.add_argument("--dataset", type=str, default=None, help="Custom path to dataset JSON")
    args = parser.parse_args()
    
    train_model(version=args.version, dataset_path=args.dataset)
