import { useState, useEffect } from "react";
import axios from "axios";
import { useAuth } from "../context/AuthContext";
import { getApiUrl } from "../config";

export interface IncidentItem {
  incident_id: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "investigating" | "contained" | "resolved" | "closed";
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  created_by: string;
  assigned_to?: string;
  affected_agent_id?: string;
  affected_model_version?: string;
  affected_policy_version?: string;
  resolution_notes?: string;
}

export function useIncidents() {
  const { token } = useAuth();
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchIncidents = async () => {
    if (!token) return;
    try {
      setLoading(true);
      const response = await axios.get<IncidentItem[]>(getApiUrl("/api/v1/incidents"), {
        headers: { Authorization: `Bearer ${token}` }
      });
      setIncidents(response.data);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || "Failed to fetch incidents");
    } finally {
      setLoading(false);
    }
  };

  const createIncident = async (payload: {
    title: string;
    description: string;
    severity: string;
    affected_agent_id?: string;
    affected_model_version?: string;
    affected_policy_version?: string;
  }) => {
    if (!token) return;
    try {
      setLoading(true);
      const response = await axios.post<IncidentItem>(getApiUrl("/api/v1/incidents"), payload, {
        headers: { Authorization: `Bearer ${token}` }
      });
      await fetchIncidents();
      return response.data;
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || "Failed to create incident";
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const updateIncident = async (incidentId: string, payload: {
    title?: string;
    description?: string;
    severity?: string;
    status?: string;
    assigned_to?: string;
    resolution_notes?: string;
  }) => {
    if (!token) return;
    try {
      setLoading(true);
      const response = await axios.patch<IncidentItem>(getApiUrl(`/api/v1/incidents/${incidentId}`), payload, {
        headers: { Authorization: `Bearer ${token}` }
      });
      await fetchIncidents();
      return response.data;
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || "Failed to update incident";
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const resolveIncident = async (incidentId: string, notes: string) => {
    if (!token) return;
    try {
      setLoading(true);
      const response = await axios.post<IncidentItem>(getApiUrl(`/api/v1/incidents/${incidentId}/resolve`), {
        resolution_notes: notes
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      await fetchIncidents();
      return response.data;
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || "Failed to resolve incident";
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (token) {
      fetchIncidents();
    }
  }, [token]);

  return {
    incidents,
    loading,
    error,
    fetchIncidents,
    createIncident,
    updateIncident,
    resolveIncident
  };
}
