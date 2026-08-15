import { useState, useEffect } from "react";
import axios from "axios";
import { getApiUrl } from "../config";

export interface AuditLogItem {
  id: string;
  agent_id: string;
  action: string;
  parameters: Record<string, any>;
  requested_at: string;
  decision: string;
  risk_level: string;
  reason: string;
  evaluated_at: string;
  model_version?: string;
  feature_schema_version?: number;
  policy_version?: string;
  request_id?: string;
  evaluation_timestamp?: string;
}

export function useAuditLogs(agentId?: string, pollIntervalMs = 4000) {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchLogs = async () => {
    try {
      const url = agentId 
        ? getApiUrl(`/api/v1/audit-log?agent_id=${agentId}`)
        : getApiUrl("/api/v1/audit-log");
      const response = await axios.get<AuditLogItem[]>(url);
      setLogs(response.data);
      setError(null);
    } catch (err: any) {
      setError(err.message || "Failed to fetch audit logs");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, pollIntervalMs);
    return () => clearInterval(interval);
  }, [agentId, pollIntervalMs]);

  return { logs, loading, error, refetch: fetchLogs };
}
