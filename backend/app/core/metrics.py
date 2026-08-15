from prometheus_client import Counter, Histogram, Gauge

# Existing metrics
ml_inference_counter = Counter(
    "aura_ml_inference_total",
    "Total machine learning inferences run",
    ["model_version", "status"]
)
ml_inference_latency = Histogram(
    "aura_ml_inference_latency_seconds",
    "Latency of ML inference in seconds",
    ["model_version"]
)
shap_errors_counter = Counter(
    "aura_shap_errors_total",
    "Total SHAP explanation failures",
    ["model_version"]
)
decisions_counter = Counter(
    "aura_decisions_total",
    "Total firewall decisions evaluated",
    ["risk_level", "policy_decision", "model_version", "policy_version"]
)

# Phase 6 metrics
model_activation_counter = Counter(
    "aura_model_activation_total",
    "Total model activations",
    ["model_version", "status"]
)
model_rollback_counter = Counter(
    "aura_model_rollback_total",
    "Total model rollbacks",
    ["model_version", "status"]
)
model_load_errors_counter = Counter(
    "aura_model_load_errors_total",
    "Total model load errors",
    ["model_version"]
)
model_checksum_failures_counter = Counter(
    "aura_model_checksum_failures_total",
    "Total model checksum failures",
    ["model_version"]
)
ml_drift_score_gauge = Gauge(
    "aura_ml_drift_score",
    "ML feature drift score",
    ["feature", "model_version"]
)
ml_drift_events_counter = Counter(
    "aura_ml_drift_events_total",
    "Total ML drift alerts",
    ["severity", "model_version"]
)
model_sync_status_gauge = Gauge(
    "aura_model_sync_status",
    "Sync status of model (1 for synchronized, 0 for degraded/error)",
    ["model_version"]
)
model_evaluations_counter = Counter(
    "aura_model_evaluations_total",
    "Total evaluation runs per model version",
    ["model_version"]
)

# Phase 7 metrics
security_events_counter = Counter(
    "aura_security_events_total",
    "Total security events logged",
    ["event_type", "severity"]
)
authentication_failures_counter = Counter(
    "aura_authentication_failures_total",
    "Total operator/agent authentication failures"
)
authorization_failures_counter = Counter(
    "aura_authorization_failures_total",
    "Total operator/agent authorization failures"
)
incidents_counter = Counter(
    "aura_incidents_total",
    "Total incidents created",
    ["severity", "status"]
)
agent_quarantines_counter = Counter(
    "aura_agent_quarantines_total",
    "Total agent quarantine events"
)
system_lockdowns_counter = Counter(
    "aura_system_lockdowns_total",
    "Total system lockdown state triggers"
)
audit_chain_verifications_counter = Counter(
    "aura_audit_chain_verifications_total",
    "Total audit chain integrity checks executed",
    ["result"]
)
audit_chain_corruption_gauge = Gauge(
    "aura_audit_chain_corruption_total",
    "Indicator of audit chain corruption (0: clean, 1: corrupted)"
)
security_alerts_counter = Counter(
    "aura_security_alerts_total",
    "Total generated security alerts",
    ["severity", "type"]
)
incident_resolution_seconds = Histogram(
    "aura_incident_resolution_seconds",
    "Time to resolve security incidents in seconds"
)
