import { useState, useEffect } from "react";
import axios from "axios";
import { useAuth } from "../context/AuthContext";
import { getApiUrl } from "../config";

export interface ModelItem {
  id: string;
  model_version: string;
  feature_schema_version: number;
  dataset_version: string;
  status: "candidate" | "active" | "retired";
  metrics: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1?: number;
    false_allow_rate?: number;
    false_block_rate?: number;
  };
  sha256: string;
  created_at: string;
  activated_at?: string;
  retired_at?: string;
}

export interface ModelHealth {
  active_model: string;
  model_status: "healthy" | "degraded" | "unavailable";
  checksum_valid: boolean;
  artifact_loaded: boolean;
  last_evaluation_at: string | null;
  drift_status: "normal" | "warning" | "critical";
  drift_score: number;
  instance_sync: "synchronized" | "degraded" | "unavailable";
}

export function useModels() {
  const { token } = useAuth();
  const [models, setModels] = useState<ModelItem[]>([]);
  const [health, setHealth] = useState<ModelHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchModels = async () => {
    if (!token) return;
    try {
      const response = await axios.get<ModelItem[]>(getApiUrl("/api/v1/models"), {
        headers: { Authorization: `Bearer ${token}` }
      });
      setModels(response.data);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || "Failed to fetch models");
    }
  };

  const fetchHealth = async () => {
    if (!token) return;
    try {
      const response = await axios.get<ModelHealth>(getApiUrl("/api/v1/models/health"), {
        headers: { Authorization: `Bearer ${token}` }
      });
      setHealth(response.data);
    } catch (err: any) {
      console.error("Failed to fetch model health:", err);
    }
  };

  const activateModel = async (version: string) => {
    if (!token) return;
    try {
      setLoading(true);
      const response = await axios.post(getApiUrl(`/api/v1/models/${version}/activate`), {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      await fetchModels();
      await fetchHealth();
      return response.data;
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || "Activation failed";
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const rollbackModel = async () => {
    if (!token) return;
    try {
      setLoading(true);
      const response = await axios.post(getApiUrl("/api/v1/models/rollback"), {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      await fetchModels();
      await fetchHealth();
      return response.data;
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || "Rollback failed";
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (token) {
      setLoading(true);
      Promise.all([fetchModels(), fetchHealth()]).finally(() => setLoading(false));
    }
  }, [token]);

  return {
    models,
    health,
    loading,
    error,
    refresh: async () => {
      setLoading(true);
      await Promise.all([fetchModels(), fetchHealth()]);
      setLoading(false);
    },
    activateModel,
    rollbackModel
  };
}
