import { useState, useEffect } from "react";
import axios from "axios";
import { useAuth } from "../context/AuthContext";
import { getApiUrl } from "../config";

export interface SecurityEventItem {
  event_id: string;
  timestamp: string;
  event_type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  source: string;
  agent_id?: string;
  operator_id?: string;
  request_id?: string;
  action_log_id?: string;
  model_version?: string;
  policy_version?: string;
  incident_id?: string;
  description: string;
  metadata_json?: any;
  previous_event_hash: string;
  event_hash: string;
}

export interface VerifyReport {
  valid: boolean;
  events_checked: number;
  first_invalid_event_id: string | null;
  verified_at: string;
}

export function useSecurity() {
  const { token } = useAuth();
  const [lockdownEnabled, setLockdownEnabled] = useState(false);
  const [auditEvents, setAuditEvents] = useState<SecurityEventItem[]>([]);
  const [auditMetadata, setAuditMetadata] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = async () => {
    if (!token) return;
    try {
      const response = await axios.get<{ lockdown_enabled: boolean }>(
        getApiUrl("/api/v1/security/status"),
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setLockdownEnabled(response.data.lockdown_enabled);
    } catch (err: any) {
      console.error("Failed to fetch lockdown status:", err);
    }
  };

  const triggerLockdown = async () => {
    if (!token) return;
    try {
      setLoading(true);
      const response = await axios.post(
        getApiUrl("/api/v1/security/lockdown"),
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setLockdownEnabled(true);
      setError(null);
      return response.data;
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || "Lockdown trigger failed";
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const releaseLockdown = async () => {
    if (!token) return;
    try {
      setLoading(true);
      const response = await axios.post(
        getApiUrl("/api/v1/security/unlock"),
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setLockdownEnabled(false);
      setError(null);
      return response.data;
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || "Lockdown release failed";
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const verifyAuditLogs = async (): Promise<VerifyReport> => {
    if (!token) throw new Error("Unauthenticated");
    try {
      setError(null);
      const response = await axios.get<VerifyReport>(
        getApiUrl("/api/v1/security/audit/verify"),
        { headers: { Authorization: `Bearer ${token}` } }
      );
      return response.data;
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || "Verification failed";
      setError(msg);
      throw err;
    }
  };

  const exportAuditLogs = async (filters: {
    start_time?: string;
    end_time?: string;
    severity?: string;
    event_type?: string;
    agent_id?: string;
    incident_id?: string;
    page?: number;
    limit?: number;
  }) => {
    if (!token) return;
    try {
      setLoading(true);
      const response = await axios.get<{
        metadata: any;
        events: SecurityEventItem[];
      }>(getApiUrl("/api/v1/security/audit/export"), {
        headers: { Authorization: `Bearer ${token}` },
        params: filters
      });
      setAuditEvents(response.data.events);
      setAuditMetadata(response.data.metadata);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || "Export failed");
    } finally {
      setLoading(false);
    }
  };

  const quarantineAgent = async (agentId: string, incidentId: string) => {
    if (!token) return;
    try {
      setLoading(true);
      const response = await axios.post(
        getApiUrl(`/api/v1/agents/${agentId}/quarantine`),
        { incident_id: incidentId },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setError(null);
      return response.data;
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || "Quarantine failed";
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (token) {
      fetchStatus();
    }
  }, [token]);

  return {
    lockdownEnabled,
    auditEvents,
    auditMetadata,
    loading,
    error,
    fetchStatus,
    triggerLockdown,
    releaseLockdown,
    verifyAuditLogs,
    exportAuditLogs,
    quarantineAgent
  };
}
